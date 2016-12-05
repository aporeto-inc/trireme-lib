package ProcessMon

import "github.com/aporeto-inc/trireme/enforcer/utils/rpc_payloads"

type ProcessManager interface {
	GetExitStatus(contextID string) bool
	SetExitStatus(contextID string, status bool) error
	KillProcess(contextID string)
	LaunchProcess(contextID string, refPid int, rpchdl rpcWrapper.RPCClient) error
}
