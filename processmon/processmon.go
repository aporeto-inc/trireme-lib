//package processmon is to manage and monitor remote enforcers.
//When we access the processmanager interface through here it acts as a singleton
//The ProcessMonitor interface is not a singleton and can be used to monitor a list of processes
package processmon

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/crypto"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/kardianos/osext"
)

var (
	// GlobalCommandArgs are command args received while invoking this command
	GlobalCommandArgs map[string]interface{}
)

var processName = ""

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

type processMonitor struct {
	processmap map[int]interface{}
	sync.RWMutex
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

//private function used with test
func setprocessname(name string) {

	processName = name
}

//collectChildExitStatus is an async function which collects status for all launched child processes
func collectChildExitStatus() {

	for {
		exitStatus := <-childExitStatus
		log.WithFields(log.Fields{"package": "ProcessMon",
			"ContextID":  exitStatus.contextID,
			"pid":        exitStatus.process,
			"ExitStatus": exitStatus.exitStatus,
		}).Info("Enforcer exited")
	}
}

// processIOReader will read from a reader and print it on the calling process
func processIOReader(fd io.Reader, contextID string, exited chan int) {
	reader := bufio.NewReader(fd)
	for {
		str, err := reader.ReadString('\n')
		if err != nil {
			exited <- 1
			fmt.Println("Error: reader failed. Exiting thread !")
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
		log.WithFields(log.Fields{"package": "ProcessMon",
			"error": err,
		}).Info("Process already dead")
		return true
	}
	return (s.(*processInfo)).deleted
}

//SetExitStatus marks the process for deletion
func (p *ProcessMon) SetExitStatus(contextID string, status bool) error {

	s, err := p.activeProcesses.Get(contextID)
	if err != nil {
		log.WithFields(log.Fields{"package": "ProcessMon",
			"error": err,
		}).Error("Process already dead")
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
		log.WithFields(log.Fields{"package": "ProcessMon",
			"msg": "Process already killed",
		}).Info("Process already killed or never launched")
		return
	}
	req := &rpcwrapper.Request{}
	resp := &rpcwrapper.Response{}
	req.Payload = s.(*processInfo).process.Pid
	err = s.(*processInfo).RPCHdl.RemoteCall(contextID, "Server.EnforcerExit", req, resp)
	if err != nil {
		s.(*processInfo).process.Kill()
	}
	s.(*processInfo).RPCHdl.DestroyRPCClient(contextID)
	os.Remove(netnspath + contextID)
	p.activeProcesses.Remove(contextID)

}

//LaunchProcess prepares the environment for the new process and launches the process
func (p *ProcessMon) LaunchProcess(contextID string, refPid int, sandboxKey string, rpchdl rpcwrapper.RPCClient, arg string, statsServerSecret string) error {
	secretLength := 32
	var cmdName string

	_, err := p.activeProcesses.Get(contextID)
	if err == nil {
		return nil
	}
	_, staterr := os.Stat(netnspath)
	if staterr != nil {
		mkerr := os.MkdirAll(netnspath, os.ModeDir)
		if mkerr != nil {
			log.WithFields(log.Fields{"package": "ProcessMon",
				"error": mkerr,
			}).Info("Could not create directory")

		}
	}

	if _, lerr := os.Stat(netnspath + contextID); lerr != nil {
		if len(sandboxKey) > 0 {
			linkErr := os.Symlink(sandboxKey,
				netnspath+contextID)
			if linkErr != nil {
				log.WithFields(log.Fields{"package": "ProcessMon",
					"error": linkErr,
				}).Error(ErrSymLinkFailed)
			}
		} else {
			linkErr := os.Symlink("/proc/"+strconv.Itoa(refPid)+"/ns/net",
				netnspath+contextID)
			if linkErr != nil {
				log.WithFields(log.Fields{"package": "ProcessMon",
					"error": linkErr,
				}).Error(ErrSymLinkFailed)
			}
		}
	}
	namedPipe := "SOCKET_PATH=/var/run/" + contextID + ".sock"

	cmdName, _ = osext.Executable()
	cmdArgs := []string{arg}

	if _, ok := GlobalCommandArgs["--log-level"]; ok {
		cmdArgs = append(cmdArgs, "--log-level")
		cmdArgs = append(cmdArgs, GlobalCommandArgs["--log-level"].(string))
	}

	cmd := exec.Command(cmdName, cmdArgs...)

	log.WithFields(log.Fields{"package": "ProcessMon",
		"command": cmdName,
		"args":    strings.Join(cmdArgs, " "),
	}).Debug("Enforcer exectued")

	stdout, err := cmd.StdoutPipe()
	stderr, err := cmd.StderrPipe()

	statschannelenv := "STATSCHANNEL_PATH=" + rpcwrapper.StatsChannel

	randomkeystring, err := crypto.GenerateRandomString(secretLength)
	if err != nil {
		//This is a more serious failure. We can't reliably control the remote enforcer
		log.WithFields(log.Fields{
			"package": "processmon",
			"Error":   err.Error(),
		}).Error("Failed to generate secret string for rpc command channel")
		return fmt.Errorf("RPC Secret failed")
	}
	rpcClientSecret := "SECRET=" + randomkeystring
	envStatsSecret := "STATS_SECRET=" + statsServerSecret
	envsandboxKey := "SANDBOX_KEY=" + sandboxKey
	cmd.Env = append(os.Environ(), []string{namedPipe, envsandboxKey, statschannelenv, rpcClientSecret, envStatsSecret, "CONTAINER_PID=" + strconv.Itoa(refPid)}...)

	err = cmd.Start()
	if err != nil {
		log.WithFields(log.Fields{"package": "ProcessMon",
			"error": err,
			"PATH":  cmdName,
		}).Error("Enforcer Binary not present in expected location")
		//Cleanup resources
		os.Remove(netnspath + contextID)
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
	//processMonWait(cmd, contextID)

	// Stdout/err processing
	go processIOReader(stdout, contextID, exited)
	go processIOReader(stderr, contextID, exited)

	rpchdl.NewRPCClient(contextID, "/var/run/"+contextID+".sock", randomkeystring)
	p.activeProcesses.Add(contextID, &processInfo{contextID: contextID,
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

//GetProcessMonitorHdl returns the handle of the process monitor
func GetProcessMonitorHdl() ProcessMonitor {
	pInstance := &processMonitor{processmap: make(map[int]interface{})}
	go pInstance.processMonitorLoop()
	return pInstance
}

//ProcessExists returns an error if the
//Magic number 0 -- when kill is called with 0 no signal is sent to the process
//Error checks are performed and we get an error if the pid does not exists
//This can be used to poll for the pid existence in poll mode
func (p *processMonitor) ProcessExists(pid int) bool {

	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}
	return true
}

//AddProcessMonList adds the pid to a list of monitored pids
//We will post an event on the passed channel when we the process exits
func (p *processMonitor) AddProcessMonList(pid int, eventChannel chan int) error {
	p.Lock()
	p.processmap[pid] = eventChannel
	p.Unlock()
	return nil
}

//TODO - This loop can get really long if we are monitoring a lot of processes
//We make a syscall for each process in the list
//netlink is another option but can be noisy if we are manging only a small set
//Will revisit this implementation
func (p *processMonitor) processMonitorLoop() {
	for {
		p.Lock()
		defer p.Unlock()
		for k, v := range p.processmap {
			p.Unlock()
			if !p.ProcessExists(k) {
				outchan := v.(chan int)
				outchan <- k
				delete(p.processmap, k)
			}
			p.Lock()
		}
		p.Unlock()
		time.Sleep(100 * time.Millisecond)

	}
}
