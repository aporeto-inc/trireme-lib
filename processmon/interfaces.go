package processmon

import "github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"

//ProcessManager interface exposes methods required by a processmonitor
type ProcessManager interface {
	GetExitStatus(contextID string) bool
	SetExitStatus(contextID string, status bool) error
	KillProcess(contextID string)
	LaunchProcess(contextID string, refPid int, rpchdl rpcwrapper.RPCClient, arg string) error
	SetnsNetPath(netpath string)
	//	ProcessExists(pid int) error
}

// ProcessMonitor is the interface of the process monitor
type ProcessMonitor interface {
	ProcessExists(pid int) bool
	AddProcessMonList(pid int, eventChannel chan int) error
}
