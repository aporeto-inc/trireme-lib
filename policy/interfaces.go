// Package policy describes a generic interface for retrieving policies.
// Different implementations are possible for environments such as Kubernetes,
// Mesos or other custom environments. An implementation has to provide
// a method for retrieving policy based on the metadata associated with the container
// and deleting the policy when the container dies. It is up to the implementation
// to decide how to generate the policy. The package also defines the basic data
// structure for communicating policy information. The implementations are responsible
// for providing all the necessary data.
package policy

import (
	"context"

	"github.com/docker/go-connections/nat"
	"go.aporeto.io/enforcerd/trireme-lib/common"
)

// A RuntimeReader allows to get the specific parameters stored in the Runtime
type RuntimeReader interface {

	// Pid returns the Pid of the Runtime.
	Pid() int

	// Name returns the process name of the Runtime.
	Name() string

	// NSPath returns the path to the namespace of the PU, if applicable
	NSPath() string

	// Tag returns  the value of the given tag.
	Tag(string) (string, bool)

	// Tags returns a copy of the list of the tags.
	Tags() *TagStore

	// Options returns a copy of the list of options.
	Options() OptionsType

	// IPAddresses returns a copy of all the IP addresses.
	IPAddresses() ExtendedMap

	// Returns the PUType for the PU
	PUType() common.PUType

	// SetServices sets the services of the runtime.
	SetServices(services []common.Service)

	// PortMap returns portmap (container port -> host port)
	PortMap() map[nat.Port][]string
}

// A Resolver must be implemented by a policy engine that receives monitor events.
type Resolver interface {

	// HandlePUEvent is called by all monitors when a PU event is generated. The implementer
	// is responsible to update all components by explicitly adding a new PU.
	HandlePUEvent(ctx context.Context, puID string, event common.Event, runtime RuntimeReader) error
}
