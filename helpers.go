package trireme

import (
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/packetprocessor"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/internal/processmon"
	"github.com/aporeto-inc/trireme-lib/internal/remoteenforcer"
	"github.com/aporeto-inc/trireme-lib/supervisor/iptablesctrl"
	"go.uber.org/zap"
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

// CleanOldState ensures all state in trireme is cleaned up.
func CleanOldState() {

	ipt, _ := iptablesctrl.NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalServer, nil)

	if err := ipt.CleanAllSynAckPacketCaptures(); err != nil {
		zap.L().Fatal("Unable to clean all syn/ack captures", zap.Error(err))
	}
}
