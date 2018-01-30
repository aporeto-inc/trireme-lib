package enforcer

import (
	"context"

	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/controller/internal/portset"
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

	// GetPortSetInstance returns nil for the proxy
	GetPortSetInstance() portset.PortSet

	// Start starts the PolicyEnforcer.
	Run(ctx context.Context) error

	// UpdateSecrets -- updates the secrets of running enforcers managed by trireme. Remote enforcers will get the secret updates with the next policy push
	UpdateSecrets(secrets secrets.Secrets) error
}
