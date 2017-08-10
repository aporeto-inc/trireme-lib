package processmon

import "github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"

//ProcessManager interface exposes methods required by a processmonitor
type ProcessManager interface {
	GetExitStatus(contextID string) bool
	SetExitStatus(contextID string, status bool) error
	KillProcess(contextID string)
	LaunchProcess(contextID string, refPid int, refNsPath string, rpchdl rpcwrapper.RPCClient, arg string, statssecret string, procMountPoint string) error
	SetnsNetPath(netpath string)
}
