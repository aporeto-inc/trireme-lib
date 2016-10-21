package controller

import "github.com/aporeto-inc/trireme/policy"

// A Controller is implementing the node control plane that captures the packets.
type Controller interface {
	AddPU(contextID string, puInfo *policy.PUInfo) error
	DeletePU(contextID string) error
	UpdatePU(contextID string, puInfo *policy.PUInfo) error
	Start() error
	Stop() error
}
