package trireme

import (
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
)

// A PolicyUpdater has the ability to receive an update for a specific policy
type PolicyUpdater interface {
	UpdatePolicy(contextID string, newPolicy *policy.PUPolicy) <-chan error
}

// A PolicyResolver is responsible of creating the Policies for a specific PU.
// The PolicyResolver also got the ability to update an already instantiated policy.
type PolicyResolver interface {
	GetPolicy(contextID string, runtimeGetter RuntimeGetter) (*policy.PUPolicy, error)
	DeletePU(contextID string) error
	SetPolicyUpdater(p PolicyUpdater) error
}

// RuntimeGetter allows to get the specific parameters stored in the Runtime
type RuntimeGetter interface {
	Pid() int
	Name() string
	Tag(string) (string, bool)
	Tags() policy.TagMap
	DefaultIPAddress() (string, bool)
	IPAddresses() map[string]string
}

// RuntimeSetter allows to get the specific parameters stored in the Runtime
type RuntimeSetter interface {
	SetPid(pid int)
	SetName(string)
	SetTags(tags policy.TagMap)
	SetIPAddresses(ipa map[string]string)
}

// Trireme is the interface to the Trireme package
type Trireme interface {
	PURuntime(contextID string) (RuntimeGetter, error)
	Start() error
	Stop() error

	monitor.ProcessingUnitsHandler
}

// PublicKeyAdder register a publicKey for a Node.
type PublicKeyAdder interface {
	PublicKeyAdd(host string, newCert []byte) error
}
