package ProcessMon

import "github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"

//ProcessManager interface exposes methods required by a processmonitor
type ProcessManager interface {
	GetExitStatus(contextID string) bool
	SetExitStatus(contextID string, status bool) error
	KillProcess(contextID string)
	LaunchProcess(contextID string, refPid int, rpchdl rpcwrapper.RPCClient) error
	SetnsNetPath(netpath string)
}
