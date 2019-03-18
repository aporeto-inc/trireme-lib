// Package supervisorproxy package implements the supervisor interface and forwards the requests on this interface
// to a remote supervisor over an rpc call.
package supervisorproxy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/processmon"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
)

//ProxyInfo is a struct used to store state for the remote launcher.
//it mirrors what is stored by the supervisor and also information to talk with the
// remote enforcer
type ProxyInfo struct {
	versionTracker cache.DataStore
	collector      collector.EventCollector
	filterQueue    *fqconfig.FilterQueue
	cfg            *runtime.Configuration
	prochdl        processmon.ProcessManager
	rpchdl         rpcwrapper.RPCClient
	initDone       map[string]bool

	sync.Mutex
}

//Supervise Calls Supervise on the remote supervisor
func (s *ProxyInfo) Supervise(contextID string, puInfo *policy.PUInfo) error {

	s.Lock()
	_, ok := s.initDone[contextID]
	cfg := s.cfg.DeepCopy()
	s.Unlock()
	if !ok {
		err := s.initRemoteSupervisor(contextID, cfg)
		if err != nil {
			return err
		}
	}

	req := &rpcwrapper.Request{
		Payload: &rpcwrapper.SuperviseRequestPayload{
			ContextID: contextID,
			Policy:    puInfo.Policy.ToPublicPolicy(),
		},
	}

	if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.Supervise, req, &rpcwrapper.Response{}); err != nil {
		s.Lock()
		delete(s.initDone, contextID)
		s.Unlock()
		return fmt.Errorf("unable to send supervise command for context id %s: %s", contextID, err)
	}

	return nil
}

// Unsupervise exported stops enforcing policy for the given IP.
func (s *ProxyInfo) Unsupervise(contextID string) error {
	s.Lock()
	delete(s.initDone, contextID)
	s.Unlock()

	s.prochdl.KillProcess(contextID)

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

	s.cfg = cfg

	return nil
}

// CleanUp implements the cleanup interface
func (s *ProxyInfo) CleanUp() error {
	for c := range s.initDone {
		s.Unsupervise(c) // nolint
	}
	return nil
}

// Run runs the proxy supervisor and initializes the cleaners.
func (s *ProxyInfo) Run(ctx context.Context) error {
	return nil
}

// NewProxySupervisor creates a new IptablesSupervisor launcher
func NewProxySupervisor(collector collector.EventCollector, enforcer enforcer.Enforcer, cfg *runtime.Configuration, rpchdl rpcwrapper.RPCClient) (*ProxyInfo, error) {

	if collector == nil {
		return nil, errors.New("collector cannot be nil")
	}

	if enforcer == nil {
		return nil, errors.New("enforcer cannot be nil")
	}

	s := &ProxyInfo{
		versionTracker: cache.NewCache("SupProxyVersionTracker"),
		collector:      collector,
		filterQueue:    enforcer.GetFilterQueue(),
		prochdl:        processmon.GetProcessManagerHdl(),
		rpchdl:         rpchdl,
		initDone:       make(map[string]bool),
		cfg:            cfg,
	}

	return s, nil

}

//InitRemoteSupervisor calls initsupervisor method on the remote
func (s *ProxyInfo) initRemoteSupervisor(contextID string, cfg *runtime.Configuration) error {

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.InitSupervisorPayload{
			Configuration: cfg,
			CaptureMethod: rpcwrapper.IPTables,
		},
	}

	if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.InitSupervisor, request, &rpcwrapper.Response{}); err != nil {
		return fmt.Errorf("unable to initialize remote supervisor for context id %s: %s", contextID, err)
	}

	s.Lock()
	s.initDone[contextID] = true
	s.Unlock()

	return nil

}

// EnableIPTablesPacketTracing enable iptables tracing
func (s *ProxyInfo) EnableIPTablesPacketTracing(ctx context.Context, contextID string, interval time.Duration) error {
	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.EnableIPTablesPacketTracingPayLoad{
			IPTablesPacketTracing: true,
			Interval:              interval,
			ContextID:             contextID,
		},
	}
	if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.EnableIPTablesPacketTracing, request, &rpcwrapper.Response{}); err != nil {
		return fmt.Errorf("Unable to enable iptables tracing for contextID %s: %s", contextID, err)
	}
	return nil
}
