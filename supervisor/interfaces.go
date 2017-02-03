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
}

// Excluder is an interface to remove specific IPs from the Trireme implementation
type Excluder interface {

	// AddExcludedIP adds an exception for the destination parameter IP, allowing all the traffic.
	AddExcludedIP(ip []string) error

	// RemoveExcludedIP removes the exception for the destination IP given in parameter.
	//RemoveExcludedIP(ip string) error
}

// Implementor is the interface of the implementation based on iptables, ipsets, remote etc
type Implementor interface {

	// ConfigureRules
	ConfigureRules(version int, contextID string, containerInfo *policy.PUInfo) error

	// UpdateRules
	UpdateRules(version int, contextID string, containerInfo *policy.PUInfo) error

	// DeleteRules
	DeleteRules(version int, context string, ipAddresses *policy.IPMap, port string, mark string) error

	// Start initializes any defaults
	Start() error

	// Stop cleans up state
	Stop() error

	// AddExcludedIP adds an exception for the destination parameter IP, allowing all the traffic.
	AddExcludedIP(ip []string) error

	// RemoveExcludedIP removes the exception for the destination IP given in parameter.
	RemoveExcludedIP(ip []string) error
}
