package policyenforcer

import (
	"github.com/aporeto-inc/trireme-lib/cache"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// A Enforcer is implementing the enforcer that will modify//analyze the capture packets
type Enforcer interface {

	// Enforce starts enforcing policies for the given policy.PUInfo.
	Enforce(contextID string, puInfo *policy.PUInfo) error

	// Unenforce stops enforcing policy for the given IP.
	Unenforce(contextID string) error

	// GetFilterQueue returns the current FilterQueueConfig.
	GetFilterQueue() *fqconfig.FilterQueue

	// GetPuFromPortCache returns the puFromPort cache used by the data path
	GetPuFromPortCache() cache.DataStore

	// Start starts the PolicyEnforcer.
	Start() error

	// Stop stops the PolicyEnforcer.
	Stop() error
}
