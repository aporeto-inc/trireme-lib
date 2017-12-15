package trireme

import (
	"os"

	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/packetprocessor"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/internal/processmon"
	"github.com/aporeto-inc/trireme-lib/internal/remoteenforcer"
	"github.com/aporeto-inc/trireme-lib/internal/supervisor/iptablesctrl"
	"go.uber.org/zap"
)

// SetLogParameters sets up environment to be passed to the remote trireme instances.
func SetLogParameters(logToConsole, logWithID bool, logLevel string, logFormat string) {

	h := processmon.GetProcessManagerHdl()
	if h == nil {
		panic("Unable to find process manager handle")
	}

	h.SetLogParameters(logToConsole, logWithID, logLevel, logFormat)
}

// GetLogParameters retrieves log parameters for Remote Enforcer.
func GetLogParameters() (logToConsole bool, logID string, logLevel string, logFormat string) {

	logLevel = os.Getenv(constants.AporetoEnvLogLevel)
	logFormat = os.Getenv(constants.AporetoEnvLogFormat)
	logID = os.Getenv(constants.AporetoEnvLogID)
	if console := os.Getenv(constants.AporetoEnvLogToConsole); console == "1" {
		logToConsole = true
	}

	return
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
