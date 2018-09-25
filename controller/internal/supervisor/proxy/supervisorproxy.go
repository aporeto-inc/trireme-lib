// Package supervisorproxy package implements the supervisor interface and forwards the requests on this interface
// to a remote supervisor over an rpc call.
package supervisorproxy

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer"
	"go.aporeto.io/trireme-lib/utils/cache"

	"go.aporeto.io/trireme-lib/controller/internal/processmon"
	"go.aporeto.io/trireme-lib/policy"
)

//ProxyInfo is a struct used to store state for the remote launcher.
//it mirrors what is stored by the supervisor and also information to talk with the
// remote enforcer
type ProxyInfo struct {
	versionTracker cache.DataStore
	collector      collector.EventCollector
	filterQueue    *fqconfig.FilterQueue
	ExcludedIPs    []string
	prochdl        processmon.ProcessManager
	rpchdl         rpcwrapper.RPCClient
	initDone       map[string]bool

	sync.Mutex
}

//Supervise Calls Supervise on the remote supervisor
func (s *ProxyInfo) Supervise(contextID string, puInfo *policy.PUInfo) error {

	s.Lock()
	_, ok := s.initDone[contextID]
	s.Unlock()
	if !ok {
		err := s.InitRemoteSupervisor(contextID, puInfo)
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
func (s *ProxyInfo) SetTargetNetworks(networks []string) error {
	s.Lock()
	defer s.Unlock()
	for contextID, done := range s.initDone {
		if done {
			request := &rpcwrapper.Request{
				Payload: &rpcwrapper.InitSupervisorPayload{
					TriremeNetworks: networks,
					CaptureMethod:   rpcwrapper.IPTables,
				},
			}

			if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.InitSupervisor, request, &rpcwrapper.Response{}); err != nil {
				return fmt.Errorf("unable to initialize remote supervisor for contextid %s: %s", contextID, err)
			}
		}
	}

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
func NewProxySupervisor(collector collector.EventCollector, enforcer enforcer.Enforcer, rpchdl rpcwrapper.RPCClient) (*ProxyInfo, error) {

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
		ExcludedIPs:    []string{},
	}

	return s, nil

}

//InitRemoteSupervisor calls initsupervisor method on the remote
func (s *ProxyInfo) InitRemoteSupervisor(contextID string, puInfo *policy.PUInfo) error {

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.InitSupervisorPayload{
			TriremeNetworks: puInfo.Policy.TriremeNetworks(),
			CaptureMethod:   rpcwrapper.IPTables,
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

//AddExcludedIPs call addexcluded ip on the remote supervisor
func (s *ProxyInfo) AddExcludedIPs(ips []string) error {
	s.ExcludedIPs = ips
	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.ExcludeIPRequestPayload{
			IPs: ips,
		},
	}

	for _, contextID := range s.rpchdl.ContextList() {
		if err := s.rpchdl.RemoteCall(contextID, "Server.AddExcludedIP", request, &rpcwrapper.Response{}); err != nil {
			return fmt.Errorf("unable to add excluded ip list for %s: %s", contextID, err)
		}
	}
	return nil
}
