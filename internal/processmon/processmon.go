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

	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme-lib/internal/remoteenforcer"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
	"github.com/aporeto-inc/trireme-lib/utils/crypto"
	"github.com/kardianos/osext"
)

var (
	// launcher supports only a global processMon instance
	launcher *processMon
)

const (
	// netNSPath holds the directory to ensure ip netns command works
	netNSPath               = "/var/run/netns/"
	processMonitorCacheName = "ProcessMonitorCache"
	secretLength            = 32
)

// processMon is an instance of processMonitor
type processMon struct {
	// netNSPath made configurable to enable running tests
	netNSPath       string
	activeProcesses *cache.Cache
	childExitStatus chan exitStatus
	// logToConsole stores if we should log to console
	logToConsole bool
	// logWithID controls whether the context ID should be provided while create a remote command
	logWithID bool
	// launcProcessArgs are arguments that are provided to all processes launched by processmon
	launcProcessArgs []string
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
	newProcessMon(netNSPath)
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
func newProcessMon(netns string) ProcessManager {

	launcher = &processMon{
		netNSPath:       netns,
		activeProcesses: cache.NewCache(processMonitorCacheName),
		childExitStatus: make(chan exitStatus, 100),
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

// SetupLogAndProcessArgs setups args that should be propagated to child processes
func (p *processMon) SetupLogAndProcessArgs(logToConsole, logWithID bool, args []string) {

	p.logToConsole = logToConsole
	p.logWithID = logWithID
	p.launcProcessArgs = args
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
func (p *processMon) getLaunchProcessCmd(arg string, contextID string) (*exec.Cmd, error) {

	cmdName, err := osext.Executable()
	if err != nil {
		return nil, err
	}

	cmdArgs := append([]string{arg}, p.launcProcessArgs...)
	if p.logWithID {
		cmdArgs = append(cmdArgs, contextID)
	}
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
		constants.AporetoEnvMountPoint + "=" + procMountPoint,
		constants.AporetoEnvContextSocket + "=" + contextID2SocketPath(contextID),
		constants.AporetoEnvStatsChannel + "=" + rpcwrapper.StatsChannel,
		constants.AporetoEnvRPCClientSecret + "=" + randomkeystring,
		constants.AporetoEnvStatsSecret + "=" + statsServerSecret,
		constants.AporetoEnvContainerPID + "=" + strconv.Itoa(refPid),
	}

	// If the PURuntime Specified a NSPath, then it is added as a new env var also.
	if refNSPath != "" {
		newEnvVars = append(newEnvVars, constants.AporetoEnvNSPath+"="+refNSPath)
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

	cmd, err := p.getLaunchProcessCmd(arg, contextID)
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
