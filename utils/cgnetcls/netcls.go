package cgnetcls

import (
	"io/ioutil"
	"path/filepath"

	"go.uber.org/zap"
)

// receiver definition.
type netCls struct {
	markchan         chan uint64
	ReleaseAgentPath string
	TriremePath      string
}

var basePath = "/sys/fs/cgroup/net_cls"

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

// GetAssignedMarkVal -- returns the mark val assigned to the group
func GetAssignedMarkVal(cgroupName string) string {
	mark, err := ioutil.ReadFile(filepath.Join(basePath, TriremeBasePath, cgroupName, markFile))

	if err != nil || len(mark) < 1 {
		zap.L().Error("Unable to read markval for cgroup", zap.String("Cgroup Name", cgroupName), zap.Error(err))
		return ""
	}
	return string(mark[:len(mark)-1])
}
