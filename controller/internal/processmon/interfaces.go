package processmon

import (
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/policy"
)

// ProcessManager interface exposes methods implemented by a processmon
type ProcessManager interface {
	KillProcess(contextID string)
	LaunchProcess(contextID string, refPid int, refNsPath string, rpchdl rpcwrapper.RPCClient, arg string, statssecret string, procMountPoint string) (bool, error)
	SetLogParameters(logToConsole, logWithID bool, logLevel string, logFormat string, compressedTags claimsheader.CompressionType)
	SetRuntimeErrorChannel(e chan *policy.RuntimeError)
}
