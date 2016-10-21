package trireme

import (
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
)

// Trireme is the interface to the Trireme package
type Trireme interface {
	PURuntime(contextID string) (policy.RuntimeGetter, error)
	Start() error
	Stop() error

	monitor.ProcessingUnitsHandler
}

// A PolicyUpdater has the ability to receive an update for a specific policy
type PolicyUpdater interface {
	UpdatePolicy(contextID string, newPolicy *policy.PUPolicy) <-chan error
}

// A PolicyResolver is responsible of creating the Policies for a specific PU.
// The PolicyResolver also got the ability to update an already instantiated policy.
type PolicyResolver interface {
	GetPolicy(contextID string, runtimeGetter policy.RuntimeGetter) (*policy.PUPolicy, error)
	DeletePU(contextID string) error
	SetPolicyUpdater(p PolicyUpdater) error
}

// PublicKeyAdder register a publicKey for a Node.
type PublicKeyAdder interface {
	PublicKeyAdd(host string, newCert []byte) error
}
