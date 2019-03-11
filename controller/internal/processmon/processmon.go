// Package processmon is to manage and monitor remote enforcers.
package processmon

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.aporeto.io/trireme-lib/utils/crypto"
	"go.uber.org/zap"
)

var (
	// launcher supports only a global processMon instance
	launcher *processMon
)

const (
	// netNSPath holds the directory to ensure ip netns command works
	netNSPath                   = "/var/run/netns/"
	processMonitorCacheName     = "ProcessMonitorCache"
	remoteEnforcerBuildName     = "remoteenforcerd"
	remoteEnforcerTempBuildPath = "/opt/aporeto/tmp/bin/"
	secretLength                = 32
)

// processMon is an instance of processMonitor
type processMon struct {
	// netNSPath made configurable to enable running tests
	netNSPath string
	// remoteEnforcerTempBuildPath made configurable to enable running tests
	remoteEnforcerTempBuildPath string
	// remoteEnforcerBuildName made configurable to enable running tests
	remoteEnforcerBuildName string
	activeProcesses         *cache.Cache
	childExitStatus         chan exitStatus
	// logToConsole stores if we should log to console.
	logToConsole bool
	// logWithID is the ID for for log files if logging to file.
	logWithID bool
	// logLevel is the level of logs for remote command.
	logLevel  string
	logFormat string
	// compressedTags instructs the remotes to use compressed tags.
	compressedTags claimsheader.CompressionType
	// runtimeErrorChannel is the channel to communicate errors to the policy engine.
	runtimeErrorChannel chan *policy.RuntimeError

	sync.Mutex
}

// processInfo stores per process information
type processInfo struct {
	contextID string
	RPCHdl    rpcwrapper.RPCClient
	process   *os.Process
	sync.Mutex
}

// exitStatus captures the exit status of a process
type exitStatus struct {
	process int
	// The contextID is optional and is primarily used by remote enforcer
	// processes to represent the namespace in which the process was running
	contextID  string
	exitStatus error
}

func init() {
	// Setup new launcher
	newProcessMon(netNSPath, remoteEnforcerTempBuildPath, remoteEnforcerBuildName)
}

// contextID2SocketPath returns the socket path to use for a givent context
func contextID2SocketPath(contextID string) string {

	if contextID == "" {
		panic("contextID is empty")
	}

	return filepath.Join(constants.SocketPath, contextID+".sock")
}

// processIOReader will read from a reader and print it on the calling process
func processIOReader(fd io.Reader, contextID string) {
	reader := bufio.NewReader(fd)
	for {
		str, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		fmt.Print("[" + contextID + "]:" + str)
	}
}

// newProcessMon is a method to create a new processmon
func newProcessMon(netns, remoteEnforcerPath, remoteEnforcerName string) ProcessManager {

	launcher = &processMon{
		remoteEnforcerTempBuildPath: remoteEnforcerPath,
		remoteEnforcerBuildName:     remoteEnforcerName,
		netNSPath:                   netns,
		activeProcesses:             cache.NewCache(processMonitorCacheName),
		childExitStatus:             make(chan exitStatus, 100),
	}

	go launcher.collectChildExitStatus()

	return launcher
}

// GetProcessManagerHdl returns a process manager handle.
func GetProcessManagerHdl() ProcessManager {
	return launcher
}

// collectChildExitStatus is an async function which collects status for all launched child processes
func (p *processMon) collectChildExitStatus() {

	for es := range p.childExitStatus {
		data, err := p.activeProcesses.Get(es.contextID)
		if err != nil {
			continue
		}

		p.activeProcesses.Remove(es.contextID) // nolint errcheck
		procInfo, ok := data.(*processInfo)
		if !ok {
			zap.L().Error("Internal error - wrong data structure")
			continue
		}
		procInfo.RPCHdl.DestroyRPCClient(es.contextID)

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
				Error:     fmt.Errorf("Remote killed:%s", es.exitStatus),
			}
		}
		zap.L().Debug("Remote enforcer exited normally",
			zap.String("nativeContextID", es.contextID),
			zap.Int("pid", es.process),
		)
	}
}

// SetLogParameters setups args that should be propagated to child processes
func (p *processMon) SetLogParameters(logToConsole, logWithID bool, logLevel string, logFormat string, compressedTags claimsheader.CompressionType) {
	p.logToConsole = logToConsole
	p.logWithID = logWithID
	p.logLevel = logLevel
	p.logFormat = logFormat
	p.compressedTags = compressedTags
}

func (p *processMon) SetRuntimeErrorChannel(e chan *policy.RuntimeError) {
	p.runtimeErrorChannel = e
}

// KillProcess sends a rpc to the process to exit failing which it will kill the process
func (p *processMon) KillProcess(contextID string) {

	p.Lock()
	s, err := p.activeProcesses.Get(contextID)
	if err != nil {
		p.Unlock()
		return
	}
	if err := p.activeProcesses.Remove(contextID); err != nil {
		zap.L().Warn("Failed to remote process from cache", zap.Error(err))
	}
	procInfo, ok := s.(*processInfo)
	if !ok {
		p.Unlock()
		return
	}
	p.Unlock()

	procInfo.Lock()
	defer procInfo.Unlock()

	req := &rpcwrapper.Request{}
	resp := &rpcwrapper.Response{}
	if procInfo.process == nil {
		zap.L().Error("KillProcess failed - process is nil")
		return
	}
	req.Payload = procInfo.process.Pid

	c := make(chan error, 1)
	go func() {
		c <- procInfo.RPCHdl.RemoteCall(contextID, remoteenforcer.EnforcerExit, req, resp)
	}()

	select {
	case err := <-c:
		if err != nil {
			zap.L().Error("Failed to stop gracefully - forcing kill",
				zap.String("Remote error", err.Error()))
		}
		procInfo.process.Kill() // nolint
	case <-time.After(5 * time.Second):
		zap.L().Error("Time out on terminating remote enforcer - forcing kill")
		procInfo.process.Kill() // nolint
	}

	procInfo.RPCHdl.DestroyRPCClient(contextID)
}

// pollStdOutAndErr polls std out and err
func (p *processMon) pollStdOutAndErr(
	cmd *exec.Cmd,
	contextID string,
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
	go processIOReader(stdout, contextID)
	go processIOReader(stderr, contextID)

	return nil
}

// getLaunchProcessCmd returns the command used to launch the enforcerd
func (p *processMon) getLaunchProcessCmd(remoteEnforcerBuildPath, remoteEnforcerName, arg string) *exec.Cmd {

	cmdName := filepath.Join(remoteEnforcerBuildPath, remoteEnforcerName)

	cmdArgs := []string{arg}
	zap.L().Debug("Enforcer executed",
		zap.String("command", cmdName),
		zap.Strings("args", cmdArgs),
	)

	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	return cmd
}

// getLaunchProcessEnvVars returns a slice of env variable strings where each string is in the form of key=value
func (p *processMon) getLaunchProcessEnvVars(
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
		constants.EnvStatsChannel + "=" + rpcwrapper.StatsChannel,
		constants.EnvDebugChannel + "=" + rpcwrapper.DebugChannel,
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

// LaunchProcess prepares the environment and launches the process. If the process
// is already launched, it will notify the caller, so that it can avoid any
// new initialization.
func (p *processMon) LaunchProcess(
	contextID string,
	refPid int,
	refNSPath string,
	rpchdl rpcwrapper.RPCClient,
	arg string,
	statsServerSecret string,
	procMountPoint string,
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
		RPCHdl:    rpchdl,
	}
	p.activeProcesses.AddOrUpdate(contextID, procInfo)
	p.Unlock()

	// We will lock the procInfo here, so a kill will have to wait and avoid any race.
	procInfo.Lock()
	defer procInfo.Unlock()

	// We check if the NetNsPath was given as parameter.
	// If it was we will use it. Otherwise we will determine it based on the PID.
	nsPath := refNSPath
	if refNSPath == "" {
		nsPath = filepath.Join(procMountPoint, strconv.Itoa(refPid), "ns/net")
	}

	hoststat, err := os.Stat(filepath.Join(procMountPoint, "1/ns/net"))
	if err != nil {
		return false, err
	}

	pidstat, err := os.Stat(nsPath)
	if err != nil {
		return false, fmt.Errorf("container pid %d not found: %s", refPid, err)
	}

	if pidstat.Sys().(*syscall.Stat_t).Ino == hoststat.Sys().(*syscall.Stat_t).Ino {
		return false, fmt.Errorf("refused to launch a remote enforcer in host namespace")
	}

	if _, err = os.Stat(p.netNSPath); err != nil {
		err = os.MkdirAll(p.netNSPath, os.ModeDir)
		if err != nil {
			zap.L().Warn("could not create directory", zap.Error(err))
		}
	}

	// A symlink is created from /var/run/netns/<context> to the NetNSPath
	contextFile := filepath.Join(p.netNSPath, contextID)
	// Remove the context file if it already exists.
	if removeErr := os.RemoveAll(contextFile); err != nil {
		zap.L().Warn("Failed to remove namespace link",
			zap.Error(removeErr))
	}
	if err = os.Symlink(nsPath, contextFile); err != nil {
		zap.L().Warn("Failed to create symlink for use by ip netns", zap.Error(err))
	}

	cmd := p.getLaunchProcessCmd(p.remoteEnforcerTempBuildPath, p.remoteEnforcerBuildName, arg)

	if err = p.pollStdOutAndErr(cmd, contextID); err != nil {
		return false, err
	}

	randomkeystring, err := crypto.GenerateRandomString(secretLength)
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
		if err1 := os.Remove(contextFile); err1 != nil {
			zap.L().Warn("Failed to clean up netns path", zap.Error(err1))
		}
		return false, fmt.Errorf("unable to start enforcer binary: %s", err)
	}

	procInfo.process = cmd.Process

	if err := rpchdl.NewRPCClient(contextID, contextID2SocketPath(contextID), randomkeystring); err != nil {
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
