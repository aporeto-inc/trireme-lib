// Package supervisorproxy package implements the supervisor interface and forwards the requests on this interface
// to a remote supervisor over an rpc call.
package supervisorproxy

import (
	"context"
	"fmt"
	"sync"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
)

//ProxyInfo is a struct used to store state for the remote launcher.
//it mirrors what is stored by the supervisor and also information to talk with the
// remote enforcer
type ProxyInfo struct {
	rpchdl   rpcwrapper.RPCClient
	initDone map[string]bool

	sync.Mutex
}

// Supervise just keeps track of the active remotes so that it can initiate updates.
func (s *ProxyInfo) Supervise(contextID string, puInfo *policy.PUInfo) error {

	s.Lock()
	defer s.Unlock()

	s.initDone[contextID] = true

	return nil
}

// Unsupervise just keeps track of the active remotes so
func (s *ProxyInfo) Unsupervise(contextID string) error {
	s.Lock()
	defer s.Unlock()

	delete(s.initDone, contextID)

	return nil
}

// SetTargetNetworks sets the target networks in case of an  update
func (s *ProxyInfo) SetTargetNetworks(cfg *runtime.Configuration) error {
	s.Lock()
	defer s.Unlock()

	for contextID, done := range s.initDone {
		if done {
			request := &rpcwrapper.Request{
				Payload: &rpcwrapper.SetTargetNetworksPayload{
					Configuration: cfg,
				},
			}
			if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.SetTargetNetworks, request, &rpcwrapper.Response{}); err != nil {
				return fmt.Errorf("unable to initialize remote supervisor for contextid %s: %s", contextID, err)
			}
		}
	}

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

// NewProxySupervisor creates a new IptablesSupervisor launcher
func NewProxySupervisor(rpchdl rpcwrapper.RPCClient) *ProxyInfo {

	return &ProxyInfo{
		initDone: make(map[string]bool),
		rpchdl:   rpchdl,
	}
}
