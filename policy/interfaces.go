// Package policy describes a generic interface for retrieving policies.
// Different implementations are possible for environments such as Kubernetes,
// Mesos or other custom environments. An implementation has to provide
// a method for retrieving policy based on the metadata associated with the container
// and deleting the policy when the container dies. It is up to the implementation
// to decide how to generate the policy.
// The package also defines the basic data structure for communicating policy
// information. The implementations are responsible for providing all the necessary
// data.
package policy

import "github.com/aporeto-inc/trireme/constants"

// A RuntimeReader allows to get the specific parameters stored in the Runtime
type RuntimeReader interface {

	// Pid returns the Pid of the Runtime.
	Pid() int

	// Name returns the process name of the Runtime.
	Name() string

	// Tag returns  the value of the given tag.
	Tag(string) (string, bool)

	// Tags returns a copy of the list of the tags.
	Tags() TagStore

	// Options returns a copy of the list of options.
	Options() ExtendedMap

	// DefaultIPAddress retutns the default IP address.
	DefaultIPAddress() (string, bool)

	// IPAddresses returns a copy of all the IP addresses.
	IPAddresses() ExtendedMap
	//Returns the PUType for the PU
	PUType() constants.PUType
}
