package trireme

import (
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
)

// Trireme is the main interface to the Trireme package.
type Trireme interface {

	// PURuntime returns a getter for a specific contextID.
	PURuntime(contextID string) (policy.RuntimeGetter, error)

	// Start starts the component.
	Start() error

	// Stop stops the component.
	Stop() error

	monitor.ProcessingUnitsHandler
}

// A PolicyUpdater has the ability to receive an update for a specific policy.
type PolicyUpdater interface {

	// UpdatePolicy updates the policy of the isolator for a container.
	UpdatePolicy(contextID string, newPolicy *policy.PUPolicy) <-chan error
}

// A PolicyResolver is responsible of creating the Policies for a specific Processing Unit.
// The PolicyResolver also got the ability to update an already instantiated policy.
type PolicyResolver interface {

	// GetPolicy returns the policy.PUPolicy associated with the given contextID using the given policy.RuntimeGetter.
	GetPolicy(contextID string, runtimeGetter policy.RuntimeGetter) (*policy.PUPolicy, error)

	// DeletePU deletes the processing unit with the given contextID.
	DeletePU(contextID string) error

	// SetPolicyUpdater sets the PolicyUpdater to use by the PolicyResolver.
	SetPolicyUpdater(p PolicyUpdater) error
}
