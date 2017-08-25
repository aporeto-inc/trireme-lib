// +build !linux,darwin windows

//Package cgnetcls implements functionality to manage classid for processes belonging to different cgroups
package cgnetcls

const (
	// TriremeBasePath is the base path for the trireme local state in the file system
	TriremeBasePath = "/trireme"
	// CgroupNameTag  identifies the cgroup name
	CgroupNameTag = "@cgroup_name"
	// CgroupMarkTag identifies the cgroup mark value
	CgroupMarkTag = "@cgroup_mark"
	// PortTag is the tag for the port values
	PortTag = "port"

	markFile             = "/net_cls.classid"
	procs                = "/cgroup.procs"
	releaseAgentConfFile = "/release_agent"
	notifyOnReleaseFile  = "/notify_on_release"
	//Initialmarkval is the start of mark values we assign to cgroup
	Initialmarkval = 100
)

//Empty receiver struct
type netCls struct {
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

// DeleteCgroup removes the cgroup
func (s *netCls) DeleteCgroup(cgroupname string) error {
	return nil
}

func (s *netCls) Deletebasepath(contextID string) bool {
	return true
}

//NewCgroupNetController returns a handle to call functions on the cgroup net_cls controller
func NewCgroupNetController(releasePath string) Cgroupnetcls {

	return &netCls{}
}

//NewDockerCgroupNetController returns a handle to call functions on the cgroup net_cls controller
func NewDockerCgroupNetController() Cgroupnetcls {

	return &netCls{}
}

// MarkVal returns a new Mark
func MarkVal() uint64 {
	return 0
}

// ListCgroupProcesses lists the processes of the cgroup
func ListCgroupProcesses(cgroupname string) ([]string, error) {
	return []string{}, nil
}
