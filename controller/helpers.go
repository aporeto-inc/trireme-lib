package controller

import (
	"context"

	"github.com/blang/semver"
	enforcerconstants "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/remoteenforcer"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.uber.org/zap"
)

// LaunchRemoteEnforcer launches a remote enforcer instance.
func LaunchRemoteEnforcer(ctx context.Context, logLevel string, logFormat string, logID string, numQueues int, agentVersion semver.Version) error {

	return remoteenforcer.LaunchRemoteEnforcer(ctx, logLevel, logFormat, logID, numQueues, agentVersion)
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
