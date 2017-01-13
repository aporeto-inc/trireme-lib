// +build !linux,darwin

//Package cgnetcls implements functionality to manage classid for processes belonging to different cgroups
package cgnetcls

const (
	basePath      = "/sys/fs/cgroup/net_cls/"
	markFile      = "/net_cls.classid"
	procs         = "/cgroup.procs"
	CgroupNameTag = "@cgroup_name"
	CgroupMarkTag = "@cgroup_mark"
	PortTag       = "@port"
)

//Empty receiver struct
type netCls struct {
	markchan chan uint64
}

//Creategroup creates a cgroup/net_cls structure and writes the allocated classid to the file.
//To add a new process to this cgroup we need to write to the cgroup file
func (s *netCls) Creategroup(cgroupname string) error {

	return nil

}

//AssignMark writes the mark value to net_cls.classid file.
func (s *netCls) AssignMark(cgroupname string, mark uint64) error {

	return nil
}

//AddProcess adds the process to the net_cls group
func (s *netCls) AddProcess(cgroupname string, pid int) error {

	return nil
}

//RemoveProcess removes the process from the cgroup by writing the pid to the
//top of net_cls cgroup cgroup.procs
func (s *netCls) RemoveProcess(cgroupname string, pid int) error {

	return nil
}

//NewCgroupNetController returns a handle to call functions on the cgroup net_cls controller
func NewCgroupNetController() Cgroupnetcls {

	return nil
}

var markval uint64 = 100

func MarkVal() <-chan string {
	ch := make(chan string)
	return ch

}
