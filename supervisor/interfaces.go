package supervisor

import "github.com/aporeto-inc/trireme/policy"

// A Supervisor is implementing the node control plane that captures the packets.
type Supervisor interface {
	AddPU(contextID string, puInfo *policy.PUInfo) error
	DeletePU(contextID string) error
	UpdatePU(contextID string, puInfo *policy.PUInfo) error
	Start() error
	Stop() error
}
