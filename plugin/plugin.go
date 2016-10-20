package plugin

import "github.com/aporeto-inc/trireme/policy"

// GenericPlugin defines the interface for an extended plugin
// The PlugIn can be used to extend the implementation of the data path
// with additional functions. The PlugiIn is called every time
// a container state changes and it is assumed to be synchronous. If
// the plugin returns an error the container will be destroyed.
type GenericPlugin interface {
	AddContainer(context string, container *policy.PUInfo) (err error)
	RemoveContainer(context string) (err error)
	UpdateContainer(context string, container *policy.PUInfo) (err error)
}
