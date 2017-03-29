// +build linux,!darwin,!windows

//Package cgnetcls implements functionality to manage classid for processes belonging to different cgroups
package cgnetcls

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	log "github.com/Sirupsen/logrus"
	"github.com/kardianos/osext"
)

const (
	basePath             = "/sys/fs/cgroup/net_cls"
	TriremeBasePath      = "/trireme"
	markFile             = "/net_cls.classid"
	procs                = "/cgroup.procs"
	CgroupNameTag        = "@cgroup_name"
	CgroupMarkTag        = "@cgroup_mark"
	PortTag              = "@usr:port"
	releaseAgentConfFile = "/release_agent"
	notifyOnReleaseFile  = "/notify_on_release"
	initialmarkval       = 100
)

var markval uint64 = initialmarkval

//Empty receiver struct
type netCls struct {
	markchan         chan uint64
	ReleaseAgentPath string
}

// Creategroup creates a cgroup/net_cls structure and writes the allocated classid to the file.
// To add a new process to this cgroup we need to write to the cgroup file
func (s *netCls) Creategroup(cgroupname string) error {

	//Create the directory structure
	_, err := os.Stat(basePath + procs)
	if os.IsNotExist(err) {
		syscall.Mount("cgroup", basePath, "cgroup", 0, "net_cls,net_prio")

	}

	os.MkdirAll((basePath + TriremeBasePath + cgroupname), 0700)

	//Write to the notify on release file and release agent files

	err = ioutil.WriteFile(basePath+releaseAgentConfFile, []byte(s.ReleaseAgentPath), 0644)
	if err != nil {
		return fmt.Errorf("Failed to register a release agent error %s", err.Error())
	}

	err = ioutil.WriteFile(basePath+notifyOnReleaseFile, []byte("1"), 0644)
	if err != nil {
		return fmt.Errorf("Failed to write to the notify file %s", err.Error())
	}

	err = ioutil.WriteFile(basePath+TriremeBasePath+notifyOnReleaseFile, []byte("1"), 0644)
	if err != nil {
		return fmt.Errorf("Failed to write to the notify file %s", err.Error())
	}

	err = ioutil.WriteFile(basePath+TriremeBasePath+cgroupname+notifyOnReleaseFile, []byte("1"), 0644)
	if err != nil {
		return fmt.Errorf("Failed to write to the notify file %s", err.Error())
	}

	return nil

}

//AssignMark writes the mark value to net_cls.classid file.
func (s *netCls) AssignMark(cgroupname string, mark uint64) error {

	_, err := os.Stat(basePath + TriremeBasePath + cgroupname)
	if os.IsNotExist(err) {
		log.WithFields(log.Fields{
			"package":    "cgnetcls",
			"Error":      err.Error(),
			"cgroupname": cgroupname,
		}).Error("Cgroup does not exist")
		return errors.New("Cgroup does not exist")
	}

	//16 is the base since the mark file expects hexadecimal values
	markval := "0x" + (strconv.FormatUint(mark, 16))

	if err := ioutil.WriteFile(basePath+TriremeBasePath+cgroupname+markFile, []byte(markval), 0644); err != nil {
		log.WithFields(log.Fields{
			"package":    "cgnetls",
			"Error":      err.Error(),
			"cgroupname": cgroupname,
		}).Error("Failed to assign mark ")
		return errors.New("Failed to  write to net_cls.classid file for new cgroup")
	}

	return nil
}

// AddProcess adds the process to the net_cls group
func (s *netCls) AddProcess(cgroupname string, pid int) error {

	_, err := os.Stat(basePath + TriremeBasePath + cgroupname)
	if os.IsNotExist(err) {
		log.WithFields(log.Fields{"package": "cgnetcls",
			"Error":      err.Error(),
			"cgroupname": cgroupname}).Error("Cgroup does not exist")
		return errors.New("Cgroup does not exist")
	}

	PID := []byte(strconv.Itoa(pid))
	if err := syscall.Kill(pid, 0); err != nil {
		return nil
	}

	if err := ioutil.WriteFile(basePath+TriremeBasePath+cgroupname+procs, PID, 0644); err != nil {
		log.WithFields(log.Fields{
			"package":    "cgnetls",
			"Error":      err.Error(),
			"cgroupname": cgroupname,
			"Pid":        pid,
		}).Error("Failed to add process to cgroup")
		return errors.New("Failed to add process to cgroup")
	}

	return nil
}

//RemoveProcess removes the process from the cgroup by writing the pid to the
//top of net_cls cgroup cgroup.procs
func (s *netCls) RemoveProcess(cgroupname string, pid int) error {

	_, err := os.Stat(basePath + TriremeBasePath + cgroupname)
	if os.IsNotExist(err) {
		log.WithFields(log.Fields{
			"package":    "cgnetcls",
			"Error":      err.Error(),
			"cgroupname": cgroupname,
		}).Error("Cgroup does not exist")
		return errors.New("Cgroup does not exist")
	}

	data, err := ioutil.ReadFile(basePath + procs)
	if err != nil || !strings.Contains(string(data), strconv.Itoa(pid)) {
		log.WithFields(log.Fields{
			"package":    "cgnetls",
			"cgroupname": cgroupname,
			"Pid":        pid,
		}).Error("Process is not a part of this cgroup")
		return errors.New("Process is not a part of this cgroup")
	}

	if err := ioutil.WriteFile(basePath+procs, []byte(strconv.Itoa(pid)), 0644); err != nil {
		log.WithFields(log.Fields{
			"package":    "cgnetls",
			"Error":      err.Error(),
			"cgroupname": cgroupname,
			"Pid":        pid,
		}).Error("Failed to remove process from cgroup")
		return errors.New("Failed to remove process to cgroup")
	}

	return nil
}

// DeleteCgroup assumes the cgroup is already empty and destroys the directory structure.
// It will return an error if the group is not empty. Use RempoveProcess to remove all processes
// Before we try deletion
func (s *netCls) DeleteCgroup(cgroupname string) error {

	_, err := os.Stat(basePath + TriremeBasePath + cgroupname)
	if os.IsNotExist(err) {
		log.WithFields(log.Fields{
			"package":    "cgnetcls",
			"Error":      err.Error(),
			"cgroupname": cgroupname,
		}).Info("Group already deleted ")
		return nil
	}

	err = os.Remove(basePath + TriremeBasePath + cgroupname)
	if err != nil {
		log.WithFields(log.Fields{
			"package":    "cgnetcls",
			"Error":      err.Error(),
			"cgroupname": cgroupname,
		}).Info("Failed to delete cgroup. perhaps Cgroup not empty")
		return fmt.Errorf("Failed to delete cgroup %s error returned %s", cgroupname, err.Error())
	}

	return nil
}

//Deletebasepath removes the base aporeto directory which comes as a separate event when we are not managing any processes
func (s *netCls) Deletebasepath(cgroupName string) bool {

	if cgroupName == TriremeBasePath {
		os.Remove(basePath + cgroupName)
		return true
	}

	return false
}

//NewCgroupNetController returns a handle to call functions on the cgroup net_cls controller
func NewCgroupNetController(releasePath string) Cgroupnetcls {
	binpath, _ := osext.Executable()
	controller := &netCls{
		markchan:         make(chan uint64),
		ReleaseAgentPath: binpath,
	}

	if releasePath != "" {
		controller.ReleaseAgentPath = releasePath
	}

	return controller
}

// MarkVal returns a new Mark Value
func MarkVal() uint64 {
	return atomic.AddUint64(&markval, 1)
}

// ListCgroupProcesses lists the processes of the cgroup
func ListCgroupProcesses(cgroupname string) ([]string, error) {

	_, err := os.Stat(basePath + TriremeBasePath + cgroupname)
	if os.IsNotExist(err) {
		return []string{}, errors.New("Cgroup does not exist")
	}

	data, err := ioutil.ReadFile(basePath + TriremeBasePath + cgroupname + "/cgroup.procs")
	if err != nil {
		return []string{}, errors.New("Cannot read procs file")
	}

	procs := []string{}
	if len(procs) == 0 {
		return procs, nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		procs = append(procs, string(line))
	}
	return procs, nil
}
