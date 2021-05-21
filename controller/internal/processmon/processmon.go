// +build linux darwin

// Package processmon is to manage and monitor remote enforcers.
package processmon

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.aporeto.io/enforcerd/internal/logging/masterlog"
	"go.aporeto.io/enforcerd/internal/utils"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/env"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/remoteenforcer"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
	"go.aporeto.io/enforcerd/trireme-lib/utils/crypto"
	"go.uber.org/zap"
)

const (
	processMonitorCacheName = "ProcessMonitorCache"
	secretLength            = 32
)

var (
	// netNSPath holds the directory to ensure ip netns command works
	netNSPath = "/var/run/netns/"

	// execCommand is to used to fake exec commands in tests.
	execCommand = exec.Command
)

// RemoteMonitor is an instance of processMonitor
type RemoteMonitor struct {
	// netNSPath made configurable to enable running tests
	netNSPath string
	// activeProcesses holds a cache of the currently active processes.
	activeProcesses *cache.Cache
	// childExitStatus is a channel to monitor the exit status of processes.
	childExitStatus chan exitStatus
	// logWithID is the ID for for log files if logging to file.
	logWithID bool
	// logLevel is the level of logs for remote command.
	logLevel string
	// logFormat selects the format of the logs for the remote.
	logFormat string
	// compressedTags instructs the remotes to use compressed tags.
	compressedTags claimsheader.CompressionType
	// numQueues is the number of nfqueus
	numQueues string
	// runtimeErrorChannel is the channel to communicate errors to the policy engine.
	runtimeErrorChannel chan *policy.RuntimeError
	// rpc is the rpc client to communicate with the remotes.
	rpc rpcwrapper.RPCClient

	sync.Mutex
}

// processInfo stores per process information
type processInfo struct {
	contextID string
	process   *os.Process
	sync.Mutex
}

// exitStatus captures the exit status of a process
type exitStatus struct {
	pid int // exitted PID
	// The contextID is optional and is primarily used by remote enforcer
	// processes to represent the namespace in which the process was running
	contextID  string
	exitStatus error
}

// New is a method to create a new remote process monitor.
func New(ctx context.Context, p *env.RemoteParameters, c chan *policy.RuntimeError, r rpcwrapper.RPCClient, numQueues int) ProcessManager {

	numQueuesStr := strconv.Itoa(numQueues)

	m := &RemoteMonitor{
		netNSPath:           netNSPath,
		activeProcesses:     cache.NewCache(processMonitorCacheName),
		childExitStatus:     make(chan exitStatus, 100),
		logWithID:           p.LogWithID,
		logLevel:            p.LogLevel,
		logFormat:           p.LogFormat,
		compressedTags:      p.CompressedTags,
		numQueues:           numQueuesStr,
		runtimeErrorChannel: c,
		rpc:                 r,
	}

	go m.collectChildExitStatus(ctx)

	return m
}

// LaunchRemoteEnforcer prepares the environment and launches the process. If the process
// is already launched, it will notify the caller, so that it can avoid any
// new initialization.
func (p *RemoteMonitor) LaunchRemoteEnforcer(
	contextID string,
	refPid int,
	refNSPath string,
	arg string,
	statsServerSecret string,
	procMountPoint string,
	enforcerType policy.EnforcerType,
) (bool, error) {
	// Locking here to get the procesinfo to avoid race conditions
	// where multiple LaunchProcess happen for the same context.
	p.Lock()
	if _, err := p.activeProcesses.Get(contextID); err == nil {
		p.Unlock()
		return false, nil
	}

	procInfo := &processInfo{
		contextID: contextID,
	}
	p.activeProcesses.AddOrUpdate(contextID, procInfo)
	p.Unlock()

	// We will lock the procInfo here, so a kill will have to wait and avoid any race.
	procInfo.Lock()
	defer procInfo.Unlock()

	var err error
	defer func() {
		// If we encoutered an error we remove it from the cache. We will
		// not be monitoring it any more. Caller is responsible for re-launching.
		if err != nil {
			p.Lock()
			defer p.Unlock()
			p.activeProcesses.Remove(contextID) // nolint errcheck
		}
	}()

	// We check if the NetNsPath was given as parameter.
	// If it was we will use it. Otherwise we will determine it based on the PID.
	nsPath := refNSPath
	if refNSPath == "" {
		nsPath = filepath.Join(procMountPoint, strconv.Itoa(refPid), "ns", "net")
	}

	var hoststat os.FileInfo
	if hoststat, err = os.Stat(filepath.Join(procMountPoint, "1", "ns", "net")); err != nil {
		return false, err
	}

	var pidstat os.FileInfo
	if pidstat, err = os.Stat(nsPath); err != nil {
		return false, fmt.Errorf("container pid %d not found: %s", refPid, err)
	}

	if pidstat.Sys().(*syscall.Stat_t).Ino == hoststat.Sys().(*syscall.Stat_t).Ino {
		err = fmt.Errorf("refused to launch a remote enforcer in host namespace")
		return false, err
	}

	if _, err = os.Stat(p.netNSPath); err != nil {
		err = os.MkdirAll(p.netNSPath, os.ModeDir)
		if err != nil {
			zap.L().Warn("could not create directory netns directory", zap.Error(err))
		}
	}

	// A symlink is created from /var/run/netns/<context> to the NetNSPath
	contextFile := filepath.Join(p.netNSPath, strings.Replace(contextID, "/", "_", -1))
	// Remove the context file if it already exists.
	if removeErr := os.RemoveAll(contextFile); err != nil {
		zap.L().Warn("Failed to remove namespace link",
			zap.Error(removeErr))
	}

	// NOTE: This is used by 'enforcer cleanup' command.
	if err = os.Symlink(nsPath, contextFile); err != nil {
		zap.L().Warn("Failed to create symlink for use by ip netns", zap.Error(err))
	}

	var randomkeystring string
	randomkeystring, err = crypto.GenerateRandomString(secretLength)
	if err != nil {
		// This is a more serious failure. We can't reliably control the remote enforcer
		return false, fmt.Errorf("unable to generate secret: %s", err)
	}

	newEnvVars := p.getLaunchProcessEnvVars(
		procMountPoint,
		contextID,
		randomkeystring,
		statsServerSecret,
		refPid,
		refNSPath,
		enforcerType,
	)

	cmd, cmdName, cmdArgs := getLaunchProcessCmd(arg)
	cmd.Env = append(os.Environ(), newEnvVars...)

	if reader, err := getCmdReader(cmd); err == nil {
		masterlog.HandleRemoteLog(reader)
	} else {
		zap.L().Error("Failed to get reader for remote logs")
	}

	if err = cmd.Start(); err != nil {
		// Cleanup resources
		if err1 := os.Remove(contextFile); err1 != nil {
			zap.L().Warn("Failed to clean up netns path", zap.Error(err1))
		}
		zap.L().Error("Unable to start remote enforcer binary", zap.Error(err))
		return false, fmt.Errorf("Unable to start remote enforcer binary: %s", err)
	}

	zap.L().Debug("Remote enforcer launched",
		zap.String("command", cmdName),
		zap.Strings("args", cmdArgs),
		zap.Int("remotePid", cmd.Process.Pid),
	)

	procInfo.process = cmd.Process
	go func() {
		status := cmd.Wait()
		p.childExitStatus <- exitStatus{
			pid:        cmd.Process.Pid,
			contextID:  contextID,
			exitStatus: status,
		}
	}()
	if err = p.rpc.NewRPCClient(contextID, contextID2SocketPath(contextID), randomkeystring); err != nil {
		return false, fmt.Errorf("failed to established rpc channel: %s", err)
	}

	return true, nil
}

// KillRemoteEnforcer sends a rpc to the process to exit failing which it will kill the process
func (p *RemoteMonitor) KillRemoteEnforcer(contextID string, force bool) error {

	p.Lock()
	s, err := p.activeProcesses.Get(contextID)
	if err != nil {
		p.Unlock()
		return fmt.Errorf("unable to find process for context: %s", contextID)
	}

	p.activeProcesses.Remove(contextID) // nolint errcheck
	p.Unlock()

	procInfo, ok := s.(*processInfo)
	if !ok {
		return fmt.Errorf("internal error - invalid type for process")
	}

	procInfo.Lock()
	defer procInfo.Unlock()

	if procInfo.process == nil {
		return fmt.Errorf("cannot find process for context: %s", contextID)
	}

	req := &rpcwrapper.Request{
		Payload: procInfo.process.Pid,
	}
	resp := &rpcwrapper.Response{}

	c := make(chan error, 1)
	go func() {
		c <- p.rpc.RemoteCall(contextID, remoteenforcer.EnforcerExit, req, resp)
	}()

	select {
	case err := <-c:
		if err != nil && force {
			zap.L().Error("Failed to stop gracefully - forcing kill",
				zap.Error(err))
			procInfo.process.Kill() // nolint
		}
	case <-time.After(5 * time.Second):
		if force {
			zap.L().Error("Time out on terminating remote enforcer - forcing kill")
			procInfo.process.Kill() // nolint
		}
	}

	p.rpc.DestroyRPCClient(contextID)

	return nil
}

// collectChildExitStatus is an async function which collects status for all launched child processes
func (p *RemoteMonitor) collectChildExitStatus(ctx context.Context) {

	defer func() {
		if r := recover(); r != nil {
			zap.L().Error("Policy engine has possibly closed the channel")
			return
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return

		case es := <-p.childExitStatus:

			// if we've already been removed from the activeProcesses then it's an expected exit.
			if err := p.activeProcesses.Remove(es.contextID); err != nil {
				continue
			}

			// ... otherwise the exit was unexpected. Stop the RPC client connection to
			// the remote enforcer and generate a runtime alarm
			p.rpc.DestroyRPCClient(es.contextID)

			if p.runtimeErrorChannel != nil {
				if es.exitStatus != nil {
					zap.L().Error("Remote enforcer exited with an error",
						zap.String("nativeContextID", es.contextID),
						zap.Int("childPid", es.pid),
						zap.Error(es.exitStatus),
					)
					p.runtimeErrorChannel <- &policy.RuntimeError{
						ContextID: es.contextID,
						Error:     fmt.Errorf("remote enforcer terminated: childPid: %d, contextID: %s, exitStatus: %s", es.pid, es.contextID, es.exitStatus.Error()),
					}
				} else {
					zap.L().Warn("Remote enforcer exited",
						zap.String("nativeContextID", es.contextID),
						zap.Int("childPid", es.pid),
					)
					p.runtimeErrorChannel <- &policy.RuntimeError{
						ContextID: es.contextID,
						Error:     fmt.Errorf("remote enforcer terminated: childPid: %d, contextID: %s", es.pid, es.contextID),
					}
				}
			}
		}
	}
}

func getCmdReader(cmd *exec.Cmd) (io.ReadCloser, error) {

	reader, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	cmd.Stderr = cmd.Stdout

	return reader, nil
}

// getLaunchProcessCmd returns the os.exec object used to launch the remote enforcerd
func getLaunchProcessCmd(arg string) (cmd *exec.Cmd, cmdName string, cmdArgs []string) {
	cmdArgs = strings.Fields(arg)
	cmdName = constants.RemoteEnforcerPath
	return execCommand(cmdName, cmdArgs...), cmdName, cmdArgs
}

// getLaunchProcessEnvVars returns a slice of env variable strings where each string is in the form of key=value
func (p *RemoteMonitor) getLaunchProcessEnvVars(
	procMountPoint string,
	contextID string,
	randomkeystring string,
	statsServerSecret string,
	refPid int,
	refNSPath string,
	enforcerType policy.EnforcerType,
) []string {

	newEnvVars := []string{
		constants.EnvMountPoint + "=" + procMountPoint,
		constants.EnvContextSocket + "=" + contextID2SocketPath(contextID),
		constants.EnvStatsChannel + "=" + constants.StatsChannel,
		constants.EnvDebugChannel + "=" + constants.DebugChannel,
		constants.EnvRPCClientSecret + "=" + randomkeystring,
		constants.EnvStatsSecret + "=" + statsServerSecret,
		constants.EnvContainerPID + "=" + strconv.Itoa(refPid),
		constants.EnvLogLevel + "=" + p.logLevel,
		constants.EnvLogFormat + "=" + p.logFormat,
		constants.EnvEnforcerType + "=" + enforcerType.String(),
		constants.EnvEnforcerdToolsDir + "=" + utils.GetEnforcerdStartupDir(),
		constants.EnvEnforcerdNFQueues + "=" + p.numQueues,
	}

	newEnvVars = append(newEnvVars, constants.EnvCompressedTags+"="+strconv.Itoa(int(p.compressedTags)))

	if p.logWithID {
		newEnvVars = append(newEnvVars, constants.EnvLogID+"="+contextID)
	}

	// If the PURuntime Specified a NSPath, then it is added as a new env var also.
	if refNSPath != "" {
		newEnvVars = append(newEnvVars, constants.EnvNSPath+"="+refNSPath)
	}

	return newEnvVars
}

// contextID2SocketPath returns the socket path to use for a givent context
func contextID2SocketPath(contextID string) string {

	if contextID == "" {
		zap.L().Fatal("contextID is empty")
	}

	hash, err := policy.Fnv32Hash(contextID)
	if err != nil {
		zap.L().Fatal("unable to hash contextID", zap.Error(err))
	}

	path := filepath.Join(constants.SocketsPath, strings.Replace(hash, "/", "_", -1)+".sock")

	// Validation enforced by Linux.
	// Ref https://man7.org/linux/man-pages/man7/unix.7.html.
	if len(path) > 107 {
		zap.L().Fatal("socket path too long", zap.String("path", path))
	}

	return path
}
