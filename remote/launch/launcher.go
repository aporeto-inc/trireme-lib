package ProcessMon

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcWrapper"
)

const (
	processName = "./enforcer"
)

//Hdl exported
type Hdl struct {
	activeProcesses *cache.Cache
}

//ProcInitInfo exported
type ProcInitInfo struct {
	EnforcerInfo  interface{}
	SupevisorInfo interface{}
}

//RemoteInitInfo exported
//var RemoteInitInfo = new(ProceInitInfo)

//ProcessInfo exported
type processInfo struct {
	contextID string
	RPCHdl    *rpcWrapper.RPCHdl
	process   *os.Process
	deleted   bool
}

var activeProcesses = cache.NewCache(nil)

// ErrEnforcerAlreadyRunning Exported
var ErrEnforcerAlreadyRunning = errors.New("Enforcer already running in this context")

// ErrSymLinkFailed Exported
var ErrSymLinkFailed = errors.New("Failed to create symlink for use by ip netns")

// ErrFailedtoLaunch Exported
var ErrFailedtoLaunch = errors.New("Failed to launch enforcer")

// ErrProcessDoesNotExists Exported
var ErrProcessDoesNotExists = errors.New("Process in that context does not exist")

//GetExitStatus exported
func GetExitStatus(contextID string) bool {

	s, err := activeProcesses.Get(contextID)
	if err != nil {
		return true
	}
	return (s.(*processInfo)).deleted
}

//SetExitStatus exported
func SetExitStatus(contextID string, status bool) {
	s, _ := activeProcesses.Get(contextID)
	val := s.(*processInfo)
	val.deleted = status
	activeProcesses.AddOrUpdate(contextID, val)
}

//KillProcess exported
func KillProcess(contextID string) {
	s, err := activeProcesses.Get(contextID)
	if err != nil {
	}

	s.(*processInfo).process.Kill()
	os.Remove(s.(*processInfo).RPCHdl.Channel)
	os.Remove("/var/run/netns/" + contextID)
	activeProcesses.Remove(contextID)

}

//LaunchProcess exported
func LaunchProcess(contextID string, refPid int) error {
	_, err := activeProcesses.Get(contextID)
	if err == nil {
		return nil //fmt.Errorf("Enforcer already running in this context")
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
		return ErrSymLinkFailed
	}
	namedPipe := "SOCKET_PATH=/tmp/" + strconv.Itoa(refPid) + ".sock"

	cmdName := "/opt/trireme/enforcer"
	cmdArgs := []string{contextID}
	cmd := exec.Command(cmdName, cmdArgs...)
	stdout, err := cmd.StdoutPipe()
	stderr, err := cmd.StderrPipe()
	cmd.Env = append(os.Environ(), []string{namedPipe, "CONTAINER_PID=" + strconv.Itoa(refPid)}...)
	cmd.Start()
	go cmd.Wait()
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)
	rpcHdl := rpcWrapper.NewRPCClient(contextID, "/tmp/"+strconv.Itoa(refPid)+".sock")
	activeProcesses.Add(contextID, &processInfo{contextID: contextID,
		process: cmd.Process,
		RPCHdl:  rpcHdl,
		deleted: false})

	return nil
}

//SetRPCClient exported
func SetRPCClient(contextID string, client *rpcWrapper.RPCHdl) error {
	val, err := activeProcesses.Get(contextID)
	if err == nil {
		val.(*processInfo).RPCHdl = client
		activeProcesses.AddOrUpdate(contextID, val)
	}
	return fmt.Errorf("Process in that context does not exist")
}

//GetProcessHdl exported
func GetProcessHdl(contextID string) (*os.Process, error) {
	val, err := activeProcesses.Get(contextID)
	if err == nil {
		return val.(*processInfo).process, err

	}
	return nil, fmt.Errorf("Process in that context does not exist")
}
