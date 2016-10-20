package interfaces

import "github.com/aporeto-inc/trireme/policy"
import "github.com/docker/docker/api/types"

// A ProcessingUnitsHandler is responsible for monitoring creation and deletion
// of ProcessingUnits.
type ProcessingUnitsHandler interface {
	HandleCreate(contextID string, runtimeInfo *policy.PURuntime) <-chan error
	HandleDelete(contextID string) <-chan error
}

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

// A Controller is implementing the node control plane that captures the packets.
type Controller interface {
	AddPU(contextID string, puInfo *policy.PUInfo) error
	DeletePU(contextID string) error
	UpdatePU(contextID string, puInfo *policy.PUInfo) error
	Start() error
	Stop() error
}

// A Datapath is implementing the DataPath that will modify//analyze the capture packets
type Datapath interface {
	AddPU(contextID string, puInfo *policy.PUInfo) error
	DeletePU(ip string) error
	UpdatePU(ipaddress string, puInfo *policy.PUInfo) error
	Start() error
	Stop() error
}

// A Monitor is implementing a low level monitoring function on some well defined primitive.
type Monitor interface {
	Start() error
	Stop() error
}

// DockerMetadataExtractor has the capability to translate Docker Information into a standard Trireme PURuntime struct.
type DockerMetadataExtractor interface {
	DockerMetadataExtract(dockerInfo *types.ContainerJSON) (*policy.PURuntime, error)
}

// Trireme is the interface to the Trireme package
type Trireme interface {
	PURuntime(contextID string) (RuntimeGetter, error)
	Start() error
	Stop() error
}

// PublicKeyAdder register a publicKey for a Node.
type PublicKeyAdder interface {
	PublicKeyAdd(host string, newCert []byte) error
}
