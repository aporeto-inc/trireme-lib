package ProcessMon

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpc_payloads"
)

const (
	processName = "./enforcer"
)

//ProcessMon exported
type ProcessMon struct {
	activeProcesses *cache.Cache
}

var launcher *ProcessMon

//ProcessInfo exported
type processInfo struct {
	contextID string
	RPCHdl    rpcWrapper.RPCClient
	process   *os.Process
	deleted   bool
}

//var activeProcesses = cache.NewCache(nil)

type exitStatus struct {
	process    int
	contextID  string
	exitStatus error
}

var childExitStatus = make(chan exitStatus, 100)

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
	go collectChildExitStatus()
}

//GetExitStatus exported
func (p *ProcessMon) GetExitStatus(contextID string) bool {

	s, err := p.activeProcesses.Get(contextID)
	if err != nil {
		log.WithFields(log.Fields{"package": "ProcessMon",
			"error": err}).Info("Process already dead")
		return true
	}
	return (s.(*processInfo)).deleted
}

//SetExitStatus exported
func (p *ProcessMon) SetExitStatus(contextID string, status bool) error {
	s, err := p.activeProcesses.Get(contextID)
	if err != nil {
		log.WithFields(log.Fields{"package": "ProcessMon",
			"error": err}).Error("Process already dead")
		return err
	}
	val := s.(*processInfo)
	val.deleted = status
	p.activeProcesses.AddOrUpdate(contextID, val)
	return nil
}

//KillProcess exported
func (p *ProcessMon) KillProcess(contextID string) {
	s, err := p.activeProcesses.Get(contextID)
	if err != nil {
		log.WithFields(log.Fields{"package": "ProcessMon",
			"msg": "Process already killed"}).Info("Process already killed or never launched")
		return
	}
	req := new(rpcWrapper.Request)
	resp := new(rpcWrapper.Response)
	req.Payload = s.(*processInfo).process.Pid
	err = s.(*processInfo).RPCHdl.RemoteCall(contextID, "Server.EnforcerExit", req, resp)
	if err != nil {
		s.(*processInfo).process.Kill()
	}
	s.(*processInfo).RPCHdl.DestroyRPCClient(contextID)
	os.Remove("/var/run/netns/" + contextID)
	p.activeProcesses.Remove(contextID)

}
func processMonWait(cmd *exec.Cmd, contextID string) {
	pid := cmd.Process.Pid
	status := cmd.Wait()
	childExitStatus <- exitStatus{process: pid, contextID: contextID, exitStatus: status}

}

func collectChildExitStatus() {
	for {
		exitStatus := <-childExitStatus
		log.WithFields(log.Fields{"package": "ProcessMon",
			"ContextID":  exitStatus.contextID,
			"pid":        exitStatus.process,
			"ExitStatus": exitStatus.exitStatus}).Info("Enforcer exited")
	}
}

//LaunchProcess exported
func (p *ProcessMon) LaunchProcess(contextID string, refPid int, rpchdl rpcWrapper.RPCClient) error {
	_, err := p.activeProcesses.Get(contextID)
	if err == nil {
		return nil
	}
	_, staterr := os.Stat("/var/run/netns")
	if staterr != nil {
		mkerr := os.MkdirAll("/var/run/netns", os.ModeDir)
		if mkerr != nil {
			log.WithFields(log.Fields{"package": "ProcessMon",
				"error": mkerr}).Info("Could not create directory")

		}
	}

	linkErr := os.Symlink("/proc/"+strconv.Itoa(refPid)+"/ns/net",
		"/var/run/netns/"+contextID)
	if linkErr != nil {
		log.WithFields(log.Fields{"package": "ProcessMon", "error": linkErr}).Error(ErrSymLinkFailed)
		//return linkErr
	}
	namedPipe := "SOCKET_PATH=/tmp/" + strconv.Itoa(refPid) + ".sock"

	cmdName := "/opt/trireme/enforcer"
	cmdArgs := []string{contextID}
	cmd := exec.Command(cmdName, cmdArgs...)
	stdout, err := cmd.StdoutPipe()
	stderr, err := cmd.StderrPipe()
	statschannelenv := "STATSCHANNEL_PATH=" + rpcWrapper.StatsChannel
	cmd.Env = append(os.Environ(), []string{namedPipe, statschannelenv, "CONTAINER_PID=" + strconv.Itoa(refPid)}...)
	err = cmd.Start()
	if err != nil {
		log.WithFields(log.Fields{"package": "ProcessMon",
			"error": err,
			"PATH":  cmdName}).Error("Enforcer Binary not present in expected location")
		//Cleanup resources
		os.Remove("/var/run/netns/" + contextID)
		return ErrBinaryNotFound
	}
	go processMonWait(cmd, contextID)
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)
	rpchdl.NewRPCClient(contextID, "/tmp/"+strconv.Itoa(refPid)+".sock")
	p.activeProcesses.Add(contextID, &processInfo{contextID: contextID,
		process: cmd.Process,
		RPCHdl:  rpchdl,
		deleted: false})

	return nil
}

//NewProcessMon exported
func NewProcessMon() ProcessManager {
	launcher = &ProcessMon{activeProcesses: cache.NewCache(nil)}
	return launcher
}

//GetProcessMonHdl exported
func GetProcessMonHdl() ProcessManager {
	if launcher == nil {
		return NewProcessMon()
	}
	return launcher

}
