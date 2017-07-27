package supervisor

import "github.com/aporeto-inc/trireme/policy"

// A Supervisor is implementing the node control plane that captures the packets.
type Supervisor interface {

	// Supervise adds a new supervised processing unit.
	Supervise(contextID string, puInfo *policy.PUInfo) error

	// Unsupervise unsupervises the given PU
	Unsupervise(contextID string) error

	// Start starts the Supervisor.
	Start() error

	// Stop stops the Supervisor.
	Stop() error

	// SetTargetNetworks sets the target networks of the supervisor
	SetTargetNetworks([]string) error
}

// Implementor is the interface of the implementation based on iptables, ipsets, remote etc
type Implementor interface {

	// ConfigureRules
	ConfigureRules(version int, contextID string, containerInfo *policy.PUInfo) error

	// UpdateRules
	UpdateRules(version int, contextID string, containerInfo *policy.PUInfo) error

	// DeleteRules
	DeleteRules(version int, context string, ipAddresses policy.ExtendedMap, port string, mark string, uid string) error

	// SetTargetNetworks sets the target networks of the supervisor
	SetTargetNetworks([]string, []string) error

	// Start initializes any defaults
	Start() error

	// Stop cleans up state
	Stop() error
}
