package controller

import (
	"os"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/internal/processmon"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor/iptablesctrl"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packetprocessor"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

// SetLogParameters sets up environment to be passed to the remote trireme instances.
func SetLogParameters(logToConsole, logWithID bool, logLevel string, logFormat string, compressedTags constants.CompressionType) {

	h := processmon.GetProcessManagerHdl()
	if h == nil {
		panic("Unable to find process manager handle")
	}

	h.SetLogParameters(logToConsole, logWithID, logLevel, logFormat, compressedTags)
}

// GetLogParameters retrieves log parameters for Remote Enforcer.
func GetLogParameters() (logToConsole bool, logID string, logLevel string, logFormat string, compressedTagsVersion constants.CompressionType) {

	logLevel = os.Getenv(constants.EnvLogLevel)
	if logLevel == "" {
		logLevel = "info"
	}
	logFormat = os.Getenv(constants.EnvLogFormat)
	if logLevel == "" {
		logFormat = "json"
	}

	if console := os.Getenv(constants.EnvLogToConsole); console == constants.EnvLogToConsoleEnable {
		logToConsole = true
	}

	logID = os.Getenv(constants.EnvLogID)

	compressedTagsVersion = constants.CompressionTypeNone
	if console := os.Getenv(constants.EnvCompressedTags); console != string(constants.CompressionTypeNone) {
		if console == string(constants.CompressionTypeV1) {
			compressedTagsVersion = constants.CompressionTypeV1
		} else if console == string(constants.CompressionTypeV2) {
			compressedTagsVersion = constants.CompressionTypeV2
		}
	}
	return
}

// LaunchRemoteEnforcer launches a remote enforcer instance.
func LaunchRemoteEnforcer(service packetprocessor.PacketProcessor) error {

	return remoteenforcer.LaunchRemoteEnforcer(service)
}

// CleanOldState ensures all state in trireme is cleaned up.
func CleanOldState() {

	ipt, _ := iptablesctrl.NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalServer)

	if err := ipt.CleanAllSynAckPacketCaptures(); err != nil {
		zap.L().Fatal("Unable to clean all syn/ack captures", zap.Error(err))
	}
}

// addTransmitterLabel adds the enforcerconstants.TransmitterLabel as a fixed label in the policy.
// The ManagementID part of the policy is used as the enforcerconstants.TransmitterLabel.
// If the Policy didn't set the ManagementID, we use the Local contextID as the
// default enforcerconstants.TransmitterLabel.
func addTransmitterLabel(contextID string, containerInfo *policy.PUInfo) {

	if containerInfo.Policy.ManagementID() == "" {
		containerInfo.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, contextID)
	} else {
		containerInfo.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, containerInfo.Policy.ManagementID())
	}
}

// MustEnforce returns true if the Policy should go Through the Enforcer/internal/supervisor.
// Return false if:
//   - PU is in host namespace.
//   - Policy got the AllowAll tag.
func mustEnforce(contextID string, containerInfo *policy.PUInfo) bool {

	if containerInfo.Policy.TriremeAction() == policy.AllowAll {
		zap.L().Debug("PUPolicy with AllowAll Action. Not policing", zap.String("contextID", contextID))
		return false
	}

	return true
}
