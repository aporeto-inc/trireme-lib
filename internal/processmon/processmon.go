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

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/crypto"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/kardianos/osext"
)

var (
	// launcher supports only a global processMon instance
	launcher *processMon

	// ErrEnforcerAlreadyRunning Exported
	ErrEnforcerAlreadyRunning = errors.New("Enforcer already running in this context")
	// ErrSymLinkFailed Exported
	ErrSymLinkFailed = errors.New("Failed to create symlink for use by ip netns")
	// ErrFailedtoLaunch Exported
	ErrFailedtoLaunch = errors.New("Failed to launch enforcer")
	// ErrProcessDoesNotExists Exported
	ErrProcessDoesNotExists = errors.New("Process in that context does not exist")
	// ErrBinaryNotFound Exported
	ErrBinaryNotFound = errors.New("Enforcer Binary not found")
)

const (
	// netnspath holds the directory to ensure ip netns command works
	netnspath               = "/var/run/netns/"
	processMonitorCacheName = "ProcessMonitorCache"
	secretLength            = 32
)

// processMon is an instance of processMonitor
type processMon struct {
	// netnspath made configurable to enable running tests
	netnspath       string
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
	newProcessMon(netnspath)
}

// contextID2SocketPath returns the socket path to use for a givent context
func contextID2SocketPath(contextID string) string {

	return filepath.Join("/var/run/" + contextID + ".sock")
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
		netnspath:       netns,
		activeProcesses: cache.NewCache(processMonitorCacheName),
		childExitStatus: make(chan exitStatus, 100),
	}

	go launcher.collectChildExitStatus()

	return launcher
}

// GetProcessManagerHdl returns a process manager handle
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
	contextFile := filepath.Join(p.netnspath, contextID)
	if err := os.Remove(contextFile); err != nil {
		zap.L().Warn("Failed to remote process from netns path", zap.Error(err))
	}

	if err := p.activeProcesses.Remove(contextID); err != nil {
		zap.L().Warn("Failed to remote process from cache", zap.Error(err))
	}
}

// pollStdOutAndErr polls std out and err
func (p *processMon) pollStdOutAndErr(cmd *exec.Cmd, exited chan int, contextID string) (initializedCount int, err error) {

	stdout, erro := cmd.StdoutPipe()
	if erro != nil {
		return initializedCount, erro
	}

	initializedCount++

	stderr, erre := cmd.StderrPipe()
	if erre != nil {
		return initializedCount, erre
	}

	initializedCount++

	// Stdout/err processing
	go processIOReader(stdout, contextID, exited)
	go processIOReader(stderr, contextID, exited)

	return initializedCount, nil
}

// getLaunchProcessCmd returns the command used to launch the enforcerd
func (p *processMon) getLaunchProcessCmd(arg string, contextID string) *exec.Cmd {

	cmdName, _ := osext.Executable()
	cmdArgs := []string{arg}

	cmdArgs = append(cmdArgs, p.launcProcessArgs...)
	if !p.logToConsole {
		cmdArgs = append(cmdArgs, contextID)
	}
	zap.L().Debug("Enforcer executed",
		zap.String("command", cmdName),
		zap.Strings("args", cmdArgs),
	)

	return exec.Command(cmdName, cmdArgs...)
}

// getLaunchProcessEnvVars returns a slice of env variable strings where each string is in the form of key=value
func (p *processMon) getLaunchProcessEnvVars(procMountPoint string, contextID string, randomkeystring string, statsServerSecret string, refPid int, refNSPath string) []string {

	mountPoint := "APORETO_ENV_PROC_MOUNTPOINT=" + procMountPoint
	namedPipe := "APORETO_ENV_SOCKET_PATH=" + contextID2SocketPath(contextID)
	statsChannel := "STATSCHANNEL_PATH=" + rpcwrapper.StatsChannel
	rpcClientSecret := "APORETO_ENV_SECRET=" + randomkeystring
	envStatsSecret := "STATS_SECRET=" + statsServerSecret
	containerPID := "CONTAINER_PID=" + strconv.Itoa(refPid)

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
		nsPath := "APORETO_ENV_NS_PATH=" + refNSPath
		newEnvVars = append(newEnvVars, nsPath)
	}

	return newEnvVars
}

// LaunchProcess prepares the environment and launches the process
func (p *processMon) LaunchProcess(contextID string, refPid int, refNSPath string, rpchdl rpcwrapper.RPCClient, arg string, statsServerSecret string, procMountPoint string) error {

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

	pidstat, pidstaterr := os.Stat(nsPath)
	hoststat, hoststaterr := os.Stat(filepath.Join(procMountPoint, "1/ns/net"))

	if pidstaterr == nil && hoststaterr == nil {
		if pidstat.Sys().(*syscall.Stat_t).Ino == hoststat.Sys().(*syscall.Stat_t).Ino {
			zap.L().Error("Refused to launch a remote enforcer in host namespace")
			return nil
		}
	} else {
		zap.L().Error("Cannot determine namespace of new container",
			zap.Error(hoststaterr),
			zap.Error(pidstaterr),
		)
	}
	_, staterr := os.Stat(p.netnspath)
	if staterr != nil {
		mkerr := os.MkdirAll(p.netnspath, os.ModeDir)
		if mkerr != nil {
			zap.L().Error("Could not create directory", zap.Error(mkerr))
		}
	}

	// A symlink is created from /var/run/netns/<context> to the NetNSPath
	contextFile := filepath.Join(p.netnspath, contextID)
	if _, lerr := os.Stat(contextFile); lerr != nil {
		linkErr := os.Symlink(nsPath, contextFile)
		if linkErr != nil {
			zap.L().Error(ErrSymLinkFailed.Error(), zap.Error(linkErr))
		}
	}

	cmd := p.getLaunchProcessCmd(arg, contextID)

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

	newEnvVars := p.getLaunchProcessEnvVars(procMountPoint, contextID, randomkeystring, statsServerSecret, refPid, refNSPath)
	cmd.Env = append(os.Environ(), newEnvVars...)

	err = cmd.Start()
	if err != nil {
		// Cleanup resources
		if oerr := os.Remove(contextFile); oerr != nil {
			zap.L().Warn("Failed to clean up netns path",
				zap.Error(err),
			)
		}
		return ErrBinaryNotFound
	}

	go func() {
		i := 0
		for i < waitForExitCount {
			<-exited
			i++
		}
		status := cmd.Wait()
		p.childExitStatus <- exitStatus{process: cmd.Process.Pid, contextID: contextID, exitStatus: status}
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
