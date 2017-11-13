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
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/crypto"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
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
func (p *processMon) SetupLogAndProcessArgs(logToConsole bool, args []string) {

	p.logToConsole = logToConsole
	p.launcProcessArgs = args
}

// KillProcess sends a rpc to the process to exit failing which it will kill the process
func (p *processMon) KillProcess(contextID string) {

	s, err := p.activeProcesses.Get(contextID)
	if err != nil {
		zap.L().Debug("Process already killed or never launched")
		return
	}
	req := &rpcwrapper.Request{}
	resp := &rpcwrapper.Response{}
	req.Payload = s.(*processInfo).process.Pid

	c := make(chan error, 1)
	go func() {
		c <- s.(*processInfo).RPCHdl.RemoteCall(contextID, "Server.EnforcerExit", req, resp)
	}()
	select {
	case kerr := <-c:
		if kerr != nil {
			zap.L().Debug("Failed to stop gracefully",
				zap.String("Remote error", kerr.Error()))
		}

		if perr := s.(*processInfo).process.Kill(); perr != nil {
			zap.L().Debug("Process is already dead",
				zap.String("Kill error", perr.Error()))
		}

	case <-time.After(5 * time.Second):
		if perr := s.(*processInfo).process.Kill(); perr != nil {
			zap.L().Info("Time out while killing process ",
				zap.Error(perr))
		}
	}

	s.(*processInfo).RPCHdl.DestroyRPCClient(contextID)
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

	cmdArgs := []string{arg}
	cmdArgs = append(cmdArgs, p.launcProcessArgs...)
	if !p.logToConsole {
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

	mountPoint := constants.AporetoEnvMountPoint + "=" + procMountPoint
	namedPipe := constants.AporetoEnvContextSocket + "=" + contextID2SocketPath(contextID)
	statsChannel := constants.AporetoEnvStatsChannel + "=" + rpcwrapper.StatsChannel
	rpcClientSecret := constants.AporetoEnvRPCClientSecret + "=" + randomkeystring
	envStatsSecret := constants.AporetoEnvStatsSecret + "=" + statsServerSecret
	containerPID := constants.AporetoEnvContainerPID + "=" + strconv.Itoa(refPid)

	newEnvVars := []string{
		mountPoint,
		namedPipe,
		statsChannel,
		rpcClientSecret,
		envStatsSecret,
		containerPID,
	}

	// If the PURuntime Specified a NSPath, then it is added as a new env var also.
	if refNSPath != "" {
		nsPath := constants.AporetoEnvNSPath + "=" + refNSPath
		newEnvVars = append(newEnvVars, nsPath)
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

	_, err := p.activeProcesses.Get(contextID)
	if err == nil {
		return nil
	}

	var nsPath string

	// We check if the NetNsPath was given as parameter.
	// If it was we will use it. Otherwise we will determine it based on the PID.
	if refNSPath == "" {
		nsPath = filepath.Join(procMountPoint, strconv.Itoa(refPid), "ns/net")
	} else {
		nsPath = refNSPath
	}

	hoststat, hoststaterr := os.Stat(filepath.Join(procMountPoint, "1/ns/net"))
	if hoststaterr != nil {
		return hoststaterr
	}

	pidstat, pidstaterr := os.Stat(nsPath)
	if pidstaterr != nil {
		return fmt.Errorf("Container pid not found: %d %s", refPid, pidstaterr.Error())
	}

	if pidstat.Sys().(*syscall.Stat_t).Ino == hoststat.Sys().(*syscall.Stat_t).Ino {
		return fmt.Errorf("Refused to launch a remote enforcer in host namespace")
	}

	if _, staterr := os.Stat(p.netNSPath); staterr != nil {
		mkerr := os.MkdirAll(p.netNSPath, os.ModeDir)
		if mkerr != nil {
			zap.L().Warn("Could not create directory", zap.Error(mkerr))
		}
	}

	// A symlink is created from /var/run/netns/<context> to the NetNSPath
	contextFile := filepath.Join(p.netNSPath, contextID)
	if _, lerr := os.Stat(contextFile); lerr != nil {
		if linkErr := os.Symlink(nsPath, contextFile); linkErr != nil {
			zap.L().Warn("Failed to create symlink for use by ip netns", zap.Error(linkErr))
		}
	}

	cmd, err := p.getLaunchProcessCmd(arg, contextID)
	if err != nil {
		return fmt.Errorf("Enforcer Binary not found: %s", err.Error())
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
		//This is a more serious failure. We can't reliably control the remote enforcer
		return fmt.Errorf("Failed to generate secret: %s", err.Error())
	}

	// Start command
	newEnvVars := p.getLaunchProcessEnvVars(
		procMountPoint,
		contextID,
		randomkeystring,
		statsServerSecret,
		refPid,
		refNSPath)
	cmd.Env = append(os.Environ(), newEnvVars...)
	if err = cmd.Start(); err != nil {
		// Cleanup resources
		if oerr := os.Remove(contextFile); oerr != nil {
			zap.L().Warn("Failed to clean up netns path", zap.Error(err))
		}
		return fmt.Errorf("Enforcer Binary could not start")
	}

	go func() {
		i := 0
		for i < waitForExitCount {
			<-exited
			i++
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
