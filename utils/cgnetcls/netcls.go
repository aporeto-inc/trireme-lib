// +build !windows

package cgnetcls

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/utils/constants"
	"go.uber.org/zap"
)

// receiver definition.
type netCls struct {
	markchan         chan uint64 // nolint: structcheck
	ReleaseAgentPath string
	TriremePath      string
}

var (
	cgroupNetClsPath string
	markval          uint64 = constants.Initialmarkval // nolint: varcheck
)

// ConfigureNetClsPath updates the cgroupNetCls path
func ConfigureNetClsPath(path string) {
	cgroupNetClsPath = path
}

// GetCgroupList geta list of all cgroup names
// TODO: only used in autoport detection, and a bad usage as well
func GetCgroupList() []string {
	var cgroupList []string

	// iterate over our different base paths from the different cgroup base paths
	for _, baseCgroupPath := range []string{common.TriremeCgroupPath, common.TriremeDockerHostNetwork} {
		filelist, err := ioutil.ReadDir(filepath.Join(cgroupNetClsPath, baseCgroupPath))
		if err == nil {
			for _, file := range filelist {
				if file.IsDir() {
					cgroupList = append(cgroupList, filepath.Join(baseCgroupPath, file.Name()))
				}
			}
		}
	}
	return cgroupList
}

// ListCgroupProcesses lists the cgroups that trireme has created
// TODO: only used in autoport detection, and a bad usage as well
func ListCgroupProcesses(cgroupname string) ([]string, error) {

	if _, err := os.Stat(filepath.Join(cgroupNetClsPath, cgroupname)); os.IsNotExist(err) {
		return []string{}, fmt.Errorf("cgroup %s does not exist: %s", cgroupname, err)
	}

	data, err := ioutil.ReadFile(filepath.Join(cgroupNetClsPath, cgroupname, "cgroup.procs"))
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

// GetAssignedMarkVal -- returns the mark val assigned to the group
// TODO: looks like dead code
func GetAssignedMarkVal(cgroupName string) string {
	mark, err := ioutil.ReadFile(filepath.Join(cgroupNetClsPath, cgroupName, markFile))

	if err != nil || len(mark) < 1 {
		zap.L().Error("Unable to read markval for cgroup", zap.String("Cgroup Name", cgroupName), zap.Error(err))
		return ""
	}
	return string(mark[:len(mark)-1])
}
