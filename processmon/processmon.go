// Package processmon is to manage and monitor remote enforcers.
// When we access the processmanager interface through here it acts as a singleton
// The ProcessMonitor interface is not a singleton and can be used to monitor a list of processes
package processmon

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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
	// GlobalCommandArgs are command args received while invoking this command
	GlobalCommandArgs map[string]interface{}
)

//ProcessMon exported
type ProcessMon struct {
	activeProcesses *cache.Cache
}

var launcher *ProcessMon

//ProcessInfo exported
type processInfo struct {
	contextID string
	RPCHdl    rpcwrapper.RPCClient
	process   *os.Process
	deleted   bool
}

//ExitStatus captures the exit status of a process
//The contextID is optional and is primarily used by remote enforcer processes
//and represents the namespace in which the process was running
type ExitStatus struct {
	process    int
	contextID  string
	exitStatus error
}

var childExitStatus = make(chan ExitStatus, 100)
var netnspath string

// ErrEnforcerAlreadyRunning Exported
var ErrEnforcerAlreadyRunning = errors.New("Enforcer already running in this context")

// ErrSymLinkFailed Exported
var ErrSymLinkFailed = errors.New("Failed to create symlink for use by ip netns")

// ErrFailedtoLaunch Exported
var ErrFailedtoLaunch = errors.New("Failed to launch enforcer")

// ErrProcessDoesNotExists Exported
var ErrProcessDoesNotExists = errors.New("Process in that context does not exist")

//ErrBinaryNotFound Exported
var ErrBinaryNotFound = errors.New("Enforcer Binary not found")

func init() {

	netnspath = "/var/run/netns/"
	go collectChildExitStatus()
}

//collectChildExitStatus is an async function which collects status for all launched child processes
func collectChildExitStatus() {

	for {
		exitStatus := <-childExitStatus
		zap.L().Debug("Remote enforcer exited",
			zap.String("nativeContextID", exitStatus.contextID),
			zap.Int("pid", exitStatus.process),
			zap.Error(exitStatus.exitStatus),
		)
	}
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

//SetnsNetPath -- only planned consumer is unit test
//Call this function if you expect network namespace links to be created in a separate path
func (p *ProcessMon) SetnsNetPath(netpath string) {

	netnspath = netpath
}

//GetExitStatus reports if the process is marked for deletion or deleted
func (p *ProcessMon) GetExitStatus(contextID string) bool {

	s, err := p.activeProcesses.Get(contextID)
	if err != nil {
		zap.L().Debug("Process already dead", zap.Error(err))
		return true
	}
	return (s.(*processInfo)).deleted
}

//SetExitStatus marks the process for deletion
func (p *ProcessMon) SetExitStatus(contextID string, status bool) error {

	s, err := p.activeProcesses.Get(contextID)
	if err != nil {
		return err
	}

	val := s.(*processInfo)
	val.deleted = status
	p.activeProcesses.AddOrUpdate(contextID, val)
	return nil
}

//KillProcess sends a rpc to the process to exit failing which it will kill the process
func (p *ProcessMon) KillProcess(contextID string) {

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
	if err := os.Remove(netnspath + contextID); err != nil {
		zap.L().Warn("Failed to remote process from netns path", zap.Error(err))
	}

	if err := p.activeProcesses.Remove(contextID); err != nil {
		zap.L().Warn("Failed to remote process from cache", zap.Error(err))
	}
}

//LaunchProcess prepares the environment for the new process and launches the process
func (p *ProcessMon) LaunchProcess(contextID string, refPid int, refNSPath string, rpchdl rpcwrapper.RPCClient, arg string, statsServerSecret string, procMountPoint string) error {
	secretLength := 32
	var cmdName string

	_, err := p.activeProcesses.Get(contextID)
	if err == nil {
		return nil
	}

	var nsPath string

	// We check if the NetNsPath was given as parameter.
	// If it was we will use it. Otherwise we will determine it based on the PID.
	if refNSPath == "" {
		nsPath = procMountPoint + "/" + strconv.Itoa(refPid) + "/ns/net"
	} else {
		nsPath = refNSPath
	}

	pidstat, pidstaterr := os.Stat(nsPath)
	hoststat, hoststaterr := os.Stat(procMountPoint + "/1/ns/net")
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
	_, staterr := os.Stat(netnspath)
	if staterr != nil {
		mkerr := os.MkdirAll(netnspath, os.ModeDir)
		if mkerr != nil {
			zap.L().Error("Could not create directory", zap.Error(mkerr))
		}
	}

	// A symlink is created from /var/run/netns/<context> to the NetNSPath
	if _, lerr := os.Stat(netnspath + contextID); lerr != nil {
		linkErr := os.Symlink(nsPath,
			netnspath+contextID)
		if linkErr != nil {
			zap.L().Error(ErrSymLinkFailed.Error(), zap.Error(linkErr))
		}
	}
	namedPipe := "APORETO_ENV_SOCKET_PATH=/var/run/" + contextID + ".sock"

	cmdName, _ = osext.Executable()
	cmdArgs := []string{arg}

	if _, ok := GlobalCommandArgs["--log-level"]; ok {
		cmdArgs = append(cmdArgs, "--log-level")
		cmdArgs = append(cmdArgs, GlobalCommandArgs["--log-level"].(string))
	}

	cmd := exec.Command(cmdName, cmdArgs...)

	zap.L().Debug("Enforcer executed",
		zap.String("command", cmdName),
		zap.Strings("args", cmdArgs),
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	statsChannel := "STATSCHANNEL_PATH=" + rpcwrapper.StatsChannel

	randomkeystring, err := crypto.GenerateRandomString(secretLength)
	if err != nil {
		//This is a more serious failure. We can't reliably control the remote enforcer
		return fmt.Errorf("Failed to generate secret: %s", err.Error())
	}
	mountPoint := "APORETO_ENV_PROC_MOUNTPOINT=" + procMountPoint
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

	cmd.Env = append(os.Environ(), newEnvVars...)

	err = cmd.Start()
	if err != nil {
		//Cleanup resources
		if oerr := os.Remove(netnspath + contextID); oerr != nil {
			zap.L().Warn("Failed to clean up netns path",
				zap.String("command", cmdName),
				zap.Error(err),
			)
		}
		return ErrBinaryNotFound
	}

	exited := make(chan int, 2)
	go func() {
		pid := cmd.Process.Pid
		i := 0
		for i < 2 {
			<-exited
			i++
		}
		status := cmd.Wait()
		childExitStatus <- ExitStatus{process: pid, contextID: contextID, exitStatus: status}
	}()

	// Stdout/err processing
	go processIOReader(stdout, contextID, exited)
	go processIOReader(stderr, contextID, exited)

	if err := rpchdl.NewRPCClient(contextID, "/var/run/"+contextID+".sock", randomkeystring); err != nil {
		return err
	}

	p.activeProcesses.AddOrUpdate(contextID, &processInfo{contextID: contextID,
		process: cmd.Process,
		RPCHdl:  rpchdl,
		deleted: false})

	return nil
}

//NewProcessMon is a method to create a new processmon
func newProcessMon() ProcessManager {

	launcher = &ProcessMon{activeProcesses: cache.NewCache()}
	return launcher
}

//GetProcessManagerHdl will ensure that we return an existing handle if one has been created.
//or return a new one if there is none
//This needs locks
func GetProcessManagerHdl() ProcessManager {

	if launcher == nil {
		return newProcessMon()
	}
	return launcher

}
