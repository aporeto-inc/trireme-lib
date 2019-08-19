// +build windows darwin

package processmon

import (
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/policy"
)

type process struct {
}

// KillProcess  unimplemented implement per platform
func (p *process) KillProcess(contextID string) {
	return
}

// LaunchProcess unimplemented implement per platform to launch a new copy of the process
func (p *process) LaunchProcess(contextID string, refPid int, refNsPath string, rpchdl rpcwrapper.RPCClient, arg string, statssecret string, procMountPoint string) error {
	return nil
}

// SetLogParameters unimplemented pass log parameters for the launched process
func (p *process) SetLogParameters(logToConsole, logWithID bool, logLevel string, logFormat string, compressedTags constants.CompressionType) {
	return
}

// SetRuntimeErrorChannel
func (p *process) SetRuntimeErrorChannel(e chan *policy.RuntimeError) {
}

// GetProcessManagerHdl returns a handle to processmanager
func GetProcessManagerHdl() ProcessManager {
	return &process{}
}
