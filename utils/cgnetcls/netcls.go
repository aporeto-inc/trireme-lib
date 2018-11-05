package cgnetcls

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// receiver definition.
type netCls struct {
	markchan         chan uint64
	ReleaseAgentPath string
	TriremePath      string
}

var basePath = "/sys/fs/cgroup/net_cls"
var markval uint64 = Initialmarkval

// GetCgroupList geta list of all cgroup names
func GetCgroupList() []string {
	var cgroupList []string
	filelist, err := ioutil.ReadDir(filepath.Join(basePath, TriremeBasePath))
	if err != nil {
		return cgroupList
	}
	for _, file := range filelist {
		if file.IsDir() {
			cgroupList = append(cgroupList, file.Name())
		}
	}
	return cgroupList
}

// ListCgroupProcesses lists the cgroups that trireme has created
func ListCgroupProcesses(cgroupname string) ([]string, error) {

	_, err := os.Stat(filepath.Join(basePath, TriremeBasePath, cgroupname))
	if os.IsNotExist(err) {
		return []string{}, fmt.Errorf("cgroup %s does not exist: %s", cgroupname, err)
	}

	data, err := ioutil.ReadFile(filepath.Join(basePath, TriremeBasePath, cgroupname, "cgroup.procs"))
	if err != nil {
		return []string{}, fmt.Errorf("cannot read procs file: %s", err)
	}

	procs := []string{}

	for _, line := range strings.Split(string(data), "\n") {
		if len(line) > 0 {
			procs = append(procs, string(line))
		}
	}

	return procs, nil
}

// GetAssignedMarkVal -- returns the mark val assigned to the group
func GetAssignedMarkVal(cgroupName string) string {
	mark, err := ioutil.ReadFile(filepath.Join(basePath, TriremeBasePath, cgroupName, markFile))

	if err != nil || len(mark) < 1 {
		zap.L().Error("Unable to read markval for cgroup", zap.String("Cgroup Name", cgroupName), zap.Error(err))
		return ""
	}
	return string(mark[:len(mark)-1])
}
