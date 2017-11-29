package trireme

import (
	"github.com/aporeto-inc/trireme-lib/enforcer/packetprocessor"
	"github.com/aporeto-inc/trireme-lib/internal/processmon"
	"github.com/aporeto-inc/trireme-lib/internal/remoteenforcer"
)

// SetupCommandArgs sets up arguments to be passed to the remote trireme instances.
func SetupCommandArgs(logToConsole, logWithID bool, subProcessArgs []string) {

	h := processmon.GetProcessManagerHdl()
	if h == nil {
		panic("Unable to find process manager handle")
	}
	h.SetupLogAndProcessArgs(logToConsole, logWithID, subProcessArgs)
}

// LaunchRemoteEnforcer launches a remote enforcer instance.
func LaunchRemoteEnforcer(service packetprocessor.PacketProcessor) error {

	return remoteenforcer.LaunchRemoteEnforcer(service)
}
