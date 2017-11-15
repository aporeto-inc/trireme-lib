package trireme

import (
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/internal/processmon"
	"github.com/aporeto-inc/trireme/internal/remoteenforcer"
)

// SetupCommandArgs sets up arguments to be passed to the remote trireme instances.
func SetupCommandArgs(logToConsole bool, subProcessArgs []string) {

	h := processmon.GetProcessManagerHdl()
	if h == nil {
		panic("Unable to find process manager handle")
	}
	h.SetupLogAndProcessArgs(logToConsole, subProcessArgs)
}

// LaunchRemoteEnforcer launches a remote enforcer instance.
func LaunchRemoteEnforcer(service enforcer.PacketProcessor) error {

	return remoteenforcer.LaunchRemoteEnforcer(service)
}
