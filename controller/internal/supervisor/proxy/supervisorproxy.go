// Package supervisorproxy package implements the supervisor interface and forwards the requests on this interface
// to a remote supervisor over an rpc call.
package supervisorproxy

import (
	"context"
	"time"

	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
)

//ProxyInfo is a struct used to store state for the remote launcher.
type ProxyInfo struct{}

// Supervise just keeps track of the active remotes so that it can initiate updates.
func (s *ProxyInfo) Supervise(contextID string, puInfo *policy.PUInfo) error {

	return nil
}

// Unsupervise just keeps track of the active remotes so
func (s *ProxyInfo) Unsupervise(contextID string) error {

	return nil
}

// SetTargetNetworks sets the target networks in case of an  update
func (s *ProxyInfo) SetTargetNetworks(cfg *runtime.Configuration) error {
	return nil
}

// CleanUp implements the cleanup interface, but it doesn't need to do anything.
func (s *ProxyInfo) CleanUp() error {
	return nil
}

// Run runs the proxy supervisor and initializes the cleaners.
func (s *ProxyInfo) Run(ctx context.Context) error {
	return nil
}

// EnableIPTablesPacketTracing enable iptables tracing
func (s *ProxyInfo) EnableIPTablesPacketTracing(ctx context.Context, contextID string, interval time.Duration) error {
	return nil
}

// NewProxySupervisor creates a new IptablesSupervisor launcher
func NewProxySupervisor() *ProxyInfo {

	return &ProxyInfo{}
}
