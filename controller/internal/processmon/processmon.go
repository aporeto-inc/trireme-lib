// Package processmon is to manage and monitor remote enforcers.
package processmon

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"go.uber.org/zap"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.aporeto.io/trireme-lib/utils/crypto"
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
	remoteEnforcerTempBuildPath = "/var/run/aporeto/tmp/bin/"
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
	logLevel       string
	logFormat      string
	compressedTags bool
}

// processInfo stores per process information
type processInfo struct {
	contextID string
	RPCHdl    rpcwrapper.RPCClient
	process   *os.Process
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

	return filepath.Join("/var/run/", contextID+".sock")
}

// processIOReader will read from a reader and print it on the calling process
func processIOReader(fd io.Reader, contextID string, exited chan int) {

	reader := bufio.NewReader(fd)

	for {
		str, err := reader.ReadString('\n')
		if err != nil {
			exited <- 1
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

	for {

		es := <-p.childExitStatus
		zap.L().Debug("Remote enforcer exited",
			zap.String("nativeContextID", es.contextID),
			zap.Int("pid", es.process),
			zap.Error(es.exitStatus),
		)
	}
}

// SetLogParameters setups args that should be propagated to child processes
func (p *processMon) SetLogParameters(logToConsole, logWithID bool, logLevel string, logFormat string, compressedTags bool) {

	p.logToConsole = logToConsole
	p.logWithID = logWithID
	p.logLevel = logLevel
	p.logFormat = logFormat
	p.compressedTags = compressedTags
}

// KillProcess sends a rpc to the process to exit failing which it will kill the process
func (p *processMon) KillProcess(contextID string) {

	s, err := p.activeProcesses.Get(contextID)
	if err != nil {
		zap.L().Debug("Process already killed or never launched")
		return
	}

	procInfo, ok := s.(*processInfo)
	if !ok {
		return
	}

	req := &rpcwrapper.Request{}
	resp := &rpcwrapper.Response{}
	req.Payload = procInfo.process.Pid

	c := make(chan error, 1)
	go func() {
		c <- procInfo.RPCHdl.RemoteCall(contextID, remoteenforcer.EnforcerExit, req, resp)
	}()

	select {
	case err := <-c:
		if err != nil {
			zap.L().Debug("Failed to stop gracefully",
				zap.String("Remote error", err.Error()))
		}

		if err := procInfo.process.Kill(); err != nil {
			zap.L().Debug("Process is already dead",
				zap.String("Kill error", err.Error()))
		}

	case <-time.After(5 * time.Second):
		if err := procInfo.process.Kill(); err != nil {
			zap.L().Info("Time out while killing process ",
				zap.Error(err))
		}
	}

	procInfo.RPCHdl.DestroyRPCClient(contextID)
	if err := os.Remove(filepath.Join(p.netNSPath, contextID)); err != nil {
		zap.L().Warn("Failed to remote process from netns path", zap.Error(err))
	}

	if err := p.activeProcesses.Remove(contextID); err != nil {
		zap.L().Warn("Failed to remote process from cache", zap.Error(err))
	}
}

// pollStdOutAndErr polls std out and err
func (p *processMon) pollStdOutAndErr(
	cmd *exec.Cmd,
	exited chan int,
	contextID string,
) (initializedCount int, err error) {

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return initializedCount, err
	}

	initializedCount++

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return initializedCount, err
	}

	initializedCount++

	// Stdout/err processing
	go processIOReader(stdout, contextID, exited)
	go processIOReader(stderr, contextID, exited)

	return initializedCount, nil
}

// getLaunchProcessCmd returns the command used to launch the enforcerd
func (p *processMon) getLaunchProcessCmd(remoteEnforcerBuildPath, remoteEnforcerName, arg string) (*exec.Cmd, error) {

	cmdName := filepath.Join(remoteEnforcerBuildPath, remoteEnforcerName)

	cmdArgs := []string{arg}
	zap.L().Debug("Enforcer executed",
		zap.String("command", cmdName),
		zap.Strings("args", cmdArgs),
	)

	return exec.Command(cmdName, cmdArgs...), nil
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
		constants.EnvRPCClientSecret + "=" + randomkeystring,
		constants.EnvStatsSecret + "=" + statsServerSecret,
		constants.EnvContainerPID + "=" + strconv.Itoa(refPid),
		constants.EnvLogLevel + "=" + p.logLevel,
		constants.EnvLogFormat + "=" + p.logFormat,
	}

	if p.compressedTags {
		newEnvVars = append(newEnvVars, constants.EnvCompressedTags+"="+constants.EnvCompressedTagsEnable)
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

// LaunchProcess prepares the environment and launches the process
func (p *processMon) LaunchProcess(
	contextID string,
	refPid int,
	refNSPath string,
	rpchdl rpcwrapper.RPCClient,
	arg string,
	statsServerSecret string,
	procMountPoint string,
) error {

	if _, err := p.activeProcesses.Get(contextID); err == nil {
		return nil
	}

	// We check if the NetNsPath was given as parameter.
	// If it was we will use it. Otherwise we will determine it based on the PID.
	nsPath := refNSPath
	if refNSPath == "" {
		nsPath = filepath.Join(procMountPoint, strconv.Itoa(refPid), "ns/net")
	}

	hoststat, err := os.Stat(filepath.Join(procMountPoint, "1/ns/net"))
	if err != nil {
		return err
	}

	pidstat, err := os.Stat(nsPath)
	if err != nil {
		return fmt.Errorf("container pid %d not found: %s", refPid, err)
	}

	if pidstat.Sys().(*syscall.Stat_t).Ino == hoststat.Sys().(*syscall.Stat_t).Ino {
		return errors.New("refused to launch a remote enforcer in host namespace")
	}

	if _, err = os.Stat(p.netNSPath); err != nil {
		err = os.MkdirAll(p.netNSPath, os.ModeDir)
		if err != nil {
			zap.L().Warn("could not create directory", zap.Error(err))
		}
	}

	// A symlink is created from /var/run/netns/<context> to the NetNSPath
	contextFile := filepath.Join(p.netNSPath, contextID)
	if _, err = os.Stat(contextFile); err != nil {
		if err = os.Symlink(nsPath, contextFile); err != nil {
			zap.L().Warn("Failed to create symlink for use by ip netns", zap.Error(err))
		}
	}

	cmd, err := p.getLaunchProcessCmd(p.remoteEnforcerTempBuildPath, p.remoteEnforcerBuildName, arg)
	if err != nil {
		return fmt.Errorf("enforcer binary not found: %s", err)
	}

	exited := make(chan int, 2)
	waitForExitCount := 0
	if p.logToConsole {
		if waitForExitCount, err = p.pollStdOutAndErr(cmd, exited, contextID); err != nil {
			return err
		}
	}

	randomkeystring, err := crypto.GenerateRandomString(secretLength)
	if err != nil {
		// This is a more serious failure. We can't reliably control the remote enforcer
		return fmt.Errorf("unable to generate secret: %s", err)
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
		return fmt.Errorf("unable to start enforcer binary: %s", err)
	}

	go func() {
		for i := 0; i < waitForExitCount; i++ {
			<-exited
		}
		status := cmd.Wait()
		p.childExitStatus <- exitStatus{
			process:    cmd.Process.Pid,
			contextID:  contextID,
			exitStatus: status,
		}
	}()

	if err := rpchdl.NewRPCClient(contextID, contextID2SocketPath(contextID), randomkeystring); err != nil {
		return err
	}

	p.activeProcesses.AddOrUpdate(contextID, &processInfo{
		contextID: contextID,
		process:   cmd.Process,
		RPCHdl:    rpchdl})

	return nil
}
