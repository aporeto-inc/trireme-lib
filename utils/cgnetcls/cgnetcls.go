// +build linux,!darwin,!windows

//Package cgnetcls implements functionality to manage classid for processes belonging to different cgroups
package cgnetcls

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/kardianos/osext"
	"go.aporeto.io/trireme-lib/common"
	"go.uber.org/zap"
)

var (
	mounted = false
)

// Creategroup creates a cgroup/net_cls structure and writes the allocated classid to the file.
// To add a new process to this cgroup we need to write to the cgroup file
func (s *netCls) Creategroup(cgroupname string) error {

	//Create the directory structure
	_, err := os.Stat(basePath + procs)
	if os.IsNotExist(err) {
		if err = syscall.Mount("cgroup", basePath, "cgroup", 0, "net_cls,net_prio"); err != nil {
			return err
		}
	}

	cgroupPath := filepath.Join(basePath, s.TriremePath, cgroupname)
	if _, err = os.Stat(cgroupPath); err == nil {
		return nil
	}

	if err = os.MkdirAll(cgroupPath, 0700); err != nil {
		return err
	}

	// Write to the notify on release file and release agent files

	if s.ReleaseAgentPath != "" {
		err = ioutil.WriteFile(filepath.Join(basePath, releaseAgentConfFile), []byte(s.ReleaseAgentPath), 0644)
		if err != nil {
			return fmt.Errorf("unable to register a release agent error: %s", err)
		}

		err = ioutil.WriteFile(filepath.Join(basePath, notifyOnReleaseFile), []byte("1"), 0644)
		if err != nil {
			return fmt.Errorf("unable to write to the notify file: %s", err)
		}

		err = ioutil.WriteFile(filepath.Join(basePath, s.TriremePath, notifyOnReleaseFile), []byte("1"), 0644)
		if err != nil {
			return fmt.Errorf("unable to write to the notify file: %s", err)
		}

		err = ioutil.WriteFile(filepath.Join(basePath, s.TriremePath, cgroupname, notifyOnReleaseFile), []byte("1"), 0644)
		if err != nil {
			return fmt.Errorf("unable to write to the notify file: %s", err)
		}
	}

	return nil

}

//AssignMark writes the mark value to net_cls.classid file.
func (s *netCls) AssignMark(cgroupname string, mark uint64) error {

	_, err := os.Stat(filepath.Join(basePath, s.TriremePath, cgroupname))
	if os.IsNotExist(err) {
		return fmt.Errorf("cgroup does not exist: %s", err)
	}

	//16 is the base since the mark file expects hexadecimal values
	markval := "0x" + (strconv.FormatUint(mark, 16))

	if err := ioutil.WriteFile(filepath.Join(basePath, s.TriremePath, cgroupname, markFile), []byte(markval), 0644); err != nil {
		return fmt.Errorf("failed to write to net_cls.classid file for new cgroup: %s", err)
	}

	return nil
}

// AddProcess adds the process to the net_cls group
func (s *netCls) AddProcess(cgroupname string, pid int) error {

	_, err := os.Stat(filepath.Join(basePath, s.TriremePath, cgroupname))
	if os.IsNotExist(err) {
		return fmt.Errorf("cannot add process. cgroup does not exist: %s", err)
	}

	PID := []byte(strconv.Itoa(pid))
	if err := syscall.Kill(pid, 0); err != nil {
		return nil
	}

	if err := ioutil.WriteFile(filepath.Join(basePath, s.TriremePath, cgroupname, procs), PID, 0644); err != nil {
		return fmt.Errorf("cannot add process: %s", err)
	}

	return nil
}

//RemoveProcess removes the process from the cgroup by writing the pid to the
//top of net_cls cgroup cgroup.procs
func (s *netCls) RemoveProcess(cgroupname string, pid int) error {

	_, err := os.Stat(filepath.Join(basePath, s.TriremePath, cgroupname))
	if os.IsNotExist(err) {
		return fmt.Errorf("cannot clean up process. cgroup does not exist: %s", err)
	}

	data, err := ioutil.ReadFile(filepath.Join(basePath, procs))
	if err != nil {
		return fmt.Errorf("cannot cleanup process: %s", err)
	}
	if !strings.Contains(string(data), strconv.Itoa(pid)) {
		return errors.New("cannot cleanup process. process is not a part of this cgroup")
	}

	if err := ioutil.WriteFile(filepath.Join(basePath, procs), []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("cannot clean up process: %s", err)
	}

	return nil
}

// DeleteCgroup assumes the cgroup is already empty and destroys the directory structure.
// It will return an error if the group is not empty. Use RempoveProcess to remove all processes
// Before we try deletion
func (s *netCls) DeleteCgroup(cgroupname string) error {

	_, err := os.Stat(filepath.Join(basePath, s.TriremePath, cgroupname))
	if os.IsNotExist(err) {
		zap.L().Debug("Group already deleted", zap.Error(err))
		return nil
	}

	err = os.Remove(filepath.Join(basePath, s.TriremePath, cgroupname))
	if err != nil {
		return fmt.Errorf("unable to delete cgroup %s: %s", cgroupname, err)
	}

	return nil
}

//Deletebasepath removes the base aporeto directory which comes as a separate event when we are not managing any processes
func (s *netCls) Deletebasepath(cgroupName string) bool {

	if cgroupName == s.TriremePath {
		if err := os.Remove(filepath.Join(basePath, cgroupName)); err != nil {
			zap.L().Error("Error when removing Trireme Base Path", zap.Error(err))
		}
		return true
	}

	return false
}

// ListCgroupProcesses returns lists of  processes in the cgroup
func (s *netCls) ListCgroupProcesses(cgroupname string) ([]string, error) {

	_, err := os.Stat(filepath.Join(basePath, s.TriremePath, cgroupname))

	if os.IsNotExist(err) {
		return []string{}, fmt.Errorf("cgroup %s does not exist: %s", cgroupname, err)
	}

	data, err := ioutil.ReadFile(filepath.Join(basePath, s.TriremePath, cgroupname, "cgroup.procs"))
	if err != nil {
		return []string{}, fmt.Errorf("cannot read procs file: %s", err)
	}

	procs := []string{}

	for _, line := range strings.Split(string(data), "\n") {
		if len(line) > 0 {
			procs = append(procs, line)
		}
	}

	return procs, nil
}

// ListAllCgroups returns a list of the cgroups that are managed in the Trireme path
func (s *netCls) ListAllCgroups(path string) []string {

	cgroups, err := ioutil.ReadDir(filepath.Join(basePath, s.TriremePath, path))
	if err != nil {
		return []string{}
	}

	names := make([]string, len(cgroups))
	for i := 0; i < len(cgroups); i++ {
		names[i] = cgroups[i].Name()
	}

	return names
}

func mountCgroupController() error {
	mounts, err := ioutil.ReadFile("/proc/mounts")
	if err != nil {
		return fmt.Errorf("Failed to read /proc/mount: %s", err)
	}

	sc := bufio.NewScanner(strings.NewReader(string(mounts)))
	var netCls = false
	var cgroupMount string
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "cgroup") {
			cgroupMount = strings.Split(sc.Text(), " ")[1]
			cgroupMount = cgroupMount[:strings.LastIndex(cgroupMount, "/")]
			if strings.Contains(sc.Text(), "net_cls") {
				basePath = strings.Split(sc.Text(), " ")[1]
				netCls = true
				return nil
			}
		}

	}

	if len(cgroupMount) == 0 {
		return fmt.Errorf("Failed to get mount points: %s", err)
	}

	if !netCls {
		basePath = cgroupMount + "/net_cls"

		if err := os.MkdirAll(basePath, 0700); err != nil {
			return fmt.Errorf("Fail to create net_cls directory: %s", err)
		}

		if err := syscall.Mount("cgroup", basePath, "cgroup", 0, "net_cls,net_prio"); err != nil {
			return fmt.Errorf("Fail to mount net_cls group: %s", err)
		}
	}
	return nil
}

// CgroupMemberCount -- Returns the cound of the number of processes in a cgroup
// TODO: looks like dead code
func CgroupMemberCount(cgroupName string) int {
	_, err := os.Stat(filepath.Join(basePath, cgroupName))
	if os.IsNotExist(err) {
		return 0
	}
	data, err := ioutil.ReadFile(filepath.Join(basePath, cgroupName, "cgroup.procs"))
	if err != nil {
		return 0
	}
	return len(data)
}

// NewDockerCgroupNetController returns a handle to call functions on the cgroup net_cls controller
func NewDockerCgroupNetController() Cgroupnetcls {

	controller := &netCls{
		markchan:         make(chan uint64),
		ReleaseAgentPath: "",
		TriremePath:      common.TriremeDockerHostNetwork,
	}

	return controller
}

//NewCgroupNetController returns a handle to call functions on the cgroup net_cls controller
func NewCgroupNetController(triremepath string, releasePath string) Cgroupnetcls {
	if !mounted {
		mounted = true
		if err := mountCgroupController(); err != nil {
			zap.L().Error("Unable to mount net_cls controller - Linux process isolation not possible",
				zap.Error(err))
		}
	}
	binpath, _ := osext.Executable()
	controller := &netCls{
		markchan:         make(chan uint64),
		ReleaseAgentPath: binpath,
		TriremePath:      "",
	}

	if releasePath != "" {
		controller.ReleaseAgentPath = releasePath
	}

	if triremepath != "" {
		controller.TriremePath = triremepath
	}

	return controller
}

// MarkVal returns a new Mark Value
func MarkVal() uint64 {
	return atomic.AddUint64(&markval, 1)
}
