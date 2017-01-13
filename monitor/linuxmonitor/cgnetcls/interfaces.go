package cgnetcls

//Cgroupnetcls interface exposing methods that can be called from outside to manage net_cls cgroups
type Cgroupnetcls interface {
	Creategroup(cgroupname string) error
	AssignMark(cgroupname string, mark uint64) error
	AddProcess(cgroupname string, pid int) error
	RemoveProcess(cgroupname string, pid int) error
	DeleteCgroup(cgroupname string) error
	Deletebasepath(contextID string) bool
}
