package processmon

import "github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"

// ProcessManager interface exposes methods implmented by a processmon
type ProcessManager interface {
	KillProcess(contextID string)
	LaunchProcess(contextID string, refPid int, refNsPath string, rpchdl rpcwrapper.RPCClient, arg string, statssecret string, procMountPoint string) error
	SetupLogAndProcessArgs(logToConsole bool, cmdArgs []string)
}
