package cgnetcls

const (
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
