// Package supervisornoop implements the supervisor interface with no operations. This is currently being used in two places:
// 1. for the supervisor proxy that actually does not need to take any action as a complement to the enforcer proxy
// 2. for enforcer implementations that do not need a supervisor to program the networks (e.g. the remote envoy authorizer enforcer)
package supervisornoop

import (
	"context"
	"time"

	"go.aporeto.io/trireme-lib/v11/controller/runtime"
	"go.aporeto.io/trireme-lib/v11/policy"
)

// NoopSupervisor is a struct to hold the implementation of the Supervisor interface
type NoopSupervisor struct{}

// Supervise just keeps track of the active remotes so that it can initiate updates.
func (s *NoopSupervisor) Supervise(contextID string, puInfo *policy.PUInfo) error {

	return nil
}

// Unsupervise just keeps track of the active remotes so
func (s *NoopSupervisor) Unsupervise(contextID string) error {

	return nil
}

// SetTargetNetworks sets the target networks in case of an  update
func (s *NoopSupervisor) SetTargetNetworks(cfg *runtime.Configuration) error {
	return nil
}

// CleanUp implements the cleanup interface, but it doesn't need to do anything.
func (s *NoopSupervisor) CleanUp() error {
	return nil
}

// Run runs the proxy supervisor and initializes the cleaners.
func (s *NoopSupervisor) Run(ctx context.Context) error {
	return nil
}

// EnableIPTablesPacketTracing enable iptables tracing
func (s *NoopSupervisor) EnableIPTablesPacketTracing(ctx context.Context, contextID string, interval time.Duration) error {
	return nil
}

// NewNoopSupervisor creates a new noop supervisor
func NewNoopSupervisor() *NoopSupervisor {

	return &NoopSupervisor{}
}
