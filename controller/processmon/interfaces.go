package processmon

import "github.com/aporeto-inc/trireme-lib/controller/enforcer/utils/rpcwrapper"

// ProcessManager interface exposes methods implemented by a processmon
type ProcessManager interface {
	KillProcess(contextID string)
	LaunchProcess(contextID string, refPid int, refNsPath string, rpchdl rpcwrapper.RPCClient, arg string, statssecret string, procMountPoint string) error
	SetLogParameters(logToConsole, logWithID bool, logLevel string, logFormat string)
}
