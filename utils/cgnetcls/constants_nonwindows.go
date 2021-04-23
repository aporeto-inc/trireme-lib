// +build !windows

package cgnetcls

const (
	markFile             = "/net_cls.classid"
	procs                = "/cgroup.procs"
	releaseAgentConfFile = "/release_agent"     // nolint: varcheck
	notifyOnReleaseFile  = "/notify_on_release" // nolint: varcheck
)
