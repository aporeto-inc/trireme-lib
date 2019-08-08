// +build windows

// Package processmon is to manage and monitor remote enforcers.
package processmon

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/env"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.aporeto.io/trireme-lib/utils/crypto"
	"go.uber.org/zap"
)

const (
	processMonitorCacheName     = "ProcessMonitorCache"
	remoteEnforcerBuildName     = "remoteenforcerd"
	remoteEnforcerTempBuildPath = "/var/run/aporeto/tmp/bin/"
	secretLength                = 32
)

var (
	// execCommand is to used to fake exec commands in tests.
	execCommand = exec.Command
)

type exitStatus struct {
	process int
	// The contextID is optional and is primarily used by remote enforcer
	// processes to represent the namespace in which the process was running
	contextID  string
	exitStatus error
}

// RemoteMonitor is an instance of processMonitor
type RemoteMonitor struct {
	// remoteEnforcerTempBuildPath made configurable to enable running tests
	remoteEnforcerTempBuildPath string
	// remoteEnforcerBuildName made configurable to enable running tests
	remoteEnforcerBuildName string
	// childExitStatus is a channel to monitor the exit status of processes.
	childExitStatus chan exitStatus
	// activeProcesses holds a cache of the currently active processes.
	activeProcesses *cache.Cache
	// runtimeErrorChannel is the channel to communicate errors to the policy engine.
	runtimeErrorChannel chan *policy.RuntimeError
	// logToConsole stores if we should log to console.
	logToConsole bool
	// logWithID is the ID for for log files if logging to file.
	logWithID bool
	// logLevel is the level of logs for remote command.
	logLevel string
	// logFormat selects the format of the logs for the remote.
	logFormat string
	// compressedTags instructs the remotes to use compressed tags.
	compressedTags claimsheader.CompressionType
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

// New is a method to create a new remote process monitor.
func New(ctx context.Context, p *env.RemoteParameters, c chan *policy.RuntimeError, r rpcwrapper.RPCClient) ProcessManager {
	return &RemoteMonitor{}

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
) (bool, error) {
	var err error
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
	procInfo.Lock()
	defer procInfo.Unlock()
	cmd := p.getLaunchProcessCmd(p.remoteEnforcerTempBuildPath, p.remoteEnforcerBuildName, arg)

	if err = p.pollStdOutAndErr(cmd); err != nil {
		return false, err
	}

	var randomkeystring string
	randomkeystring, err = crypto.GenerateRandomString(secretLength)
	if err != nil {
		// This is a more serious failure. We can't reliably control the remote enforcer
		return false, fmt.Errorf("unable to generate secret: %s", err)
	}

	// Start command
	newEnvVars := p.getLaunchProcessEnvVars(
		procMountPoint,
		contextID,
		randomkeystring,
		statsServerSecret,
		refPid,
		refNSPath,
	)
	cmd.Env = append(os.Environ(), newEnvVars...)

	if err = cmd.Start(); err != nil {
		// Cleanup resources
		// if err1 := os.Remove(contextFile); err1 != nil {
		// 	zap.L().Warn("Failed to clean up netns path", zap.Error(err1))
		// }
		return false, fmt.Errorf("unable to start enforcer binary: %s", err)
	}

	procInfo.process = cmd.Process

	if err = p.rpc.NewRPCClient(contextID, contextID2SocketPath(contextID), randomkeystring); err != nil {
		return false, fmt.Errorf("failed to established rpc channel: %s", err)
	}

	go func() {
		status := cmd.Wait()
		p.childExitStatus <- exitStatus{
			process:    cmd.Process.Pid,
			contextID:  contextID,
			exitStatus: status,
		}
	}()

	return true, nil
}

// KillRemoteEnforcer sends a rpc to the process to exit failing which it will kill the process
func (p *RemoteMonitor) KillRemoteEnforcer(contextID string, force bool) error {
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

			if err := p.activeProcesses.Remove(es.contextID); err != nil {
				continue
			}

			p.rpc.DestroyRPCClient(es.contextID)

			if p.runtimeErrorChannel != nil {
				if es.exitStatus != nil {
					zap.L().Error("Remote enforcer exited with an error",
						zap.String("nativeContextID", es.contextID),
						zap.Int("pid", es.process),
						zap.Error(es.exitStatus),
					)
				} else {
					zap.L().Warn("Remote enforcer exited",
						zap.String("nativeContextID", es.contextID),
						zap.Int("pid", es.process),
					)
				}
				p.runtimeErrorChannel <- &policy.RuntimeError{
					ContextID: es.contextID,
					Error:     fmt.Errorf("remote enforcer terminated: %s", es.exitStatus),
				}
			}

		}
	}
}

// pollStdOutAndErr polls std out and err
func (p *RemoteMonitor) pollStdOutAndErr(
	cmd *exec.Cmd,
) (err error) {

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	// Stdout/err processing
	go processIOReader(stdout)
	go processIOReader(stderr)

	return nil
}

// processIOReader will read from a reader and print it on the calling process
func processIOReader(fd io.Reader) {
	reader := bufio.NewReader(fd)
	for {
		str, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		fmt.Print(str)
	}
}

// getLaunchProcessCmd returns the command used to launch the enforcerd
func (p *RemoteMonitor) getLaunchProcessCmd(remoteEnforcerBuildPath, remoteEnforcerName, arg string) *exec.Cmd {

	cmdName := filepath.Join(remoteEnforcerBuildPath, remoteEnforcerName)

	cmdArgs := []string{arg}
	zap.L().Debug("Enforcer executed",
		zap.String("command", cmdName),
		zap.Strings("args", cmdArgs),
	)

	return execCommand(cmdName, cmdArgs...)
}

// getLaunchProcessEnvVars returns a slice of env variable strings where each string is in the form of key=value
func (p *RemoteMonitor) getLaunchProcessEnvVars(
	procMountPoint string,
	contextID string,
	randomkeystring string,
	statsServerSecret string,
	refPid int,
	refNSPath string,
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
	}

	if p.compressedTags != claimsheader.CompressionTypeNone {
		newEnvVars = append(newEnvVars, constants.EnvCompressedTags+"="+string(p.compressedTags))
	}

	if p.logToConsole {
		newEnvVars = append(newEnvVars, constants.EnvLogToConsole+"="+constants.EnvLogToConsoleEnable)
	}

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
		panic("contextID is empty")
	}

	return filepath.Join("/var/run/", strings.Replace(contextID, "/", "_", -1)+".sock")
}
