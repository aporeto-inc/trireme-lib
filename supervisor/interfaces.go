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
