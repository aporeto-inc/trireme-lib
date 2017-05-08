// Package supervisorproxy package implements the supervisor interface and forwards the requests on this interface
// to a remote supervisor over an rpc call.
package supervisorproxy

import (
	"fmt"
	"strconv"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"

	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/processmon"
)

//ProxyInfo is a struct used to store state for the remote launcher.
//it mirrors what is stored by the supervisor and also information to talk with the
// remote enforcer
type ProxyInfo struct {
	versionTracker    cache.DataStore
	collector         collector.EventCollector
	networkQueues     string
	applicationQueues string
	ExcludedIPs       []string
	prochdl           processmon.ProcessManager
	rpchdl            rpcwrapper.RPCClient
	initDone          map[string]bool
}

//Supervise Calls Supervise on the remote supervisor
func (s *ProxyInfo) Supervise(contextID string, puInfo *policy.PUInfo) error {

	if _, ok := s.initDone[contextID]; !ok {
		err := s.InitRemoteSupervisor(contextID, puInfo)
		if err != nil {
			return err
		}
	}

	req := &rpcwrapper.Request{
		Payload: &rpcwrapper.SuperviseRequestPayload{
			ContextID:        contextID,
			ManagementID:     puInfo.Policy.ManagementID,
			TriremeAction:    puInfo.Policy.TriremeAction,
			ApplicationACLs:  puInfo.Policy.ApplicationACLs(),
			NetworkACLs:      puInfo.Policy.NetworkACLs(),
			PolicyIPs:        puInfo.Policy.IPAddresses(),
			Annotations:      puInfo.Policy.Annotations(),
			Identity:         puInfo.Policy.Identity(),
			ReceiverRules:    puInfo.Policy.ReceiverRules(),
			TransmitterRules: puInfo.Policy.TransmitterRules(),
			ExcludedNetworks: puInfo.Policy.ExcludedNetworks(),
			TriremeNetworks:  puInfo.Policy.TriremeNetworks(),
		},
	}

	if err := s.rpchdl.RemoteCall(contextID, "Server.Supervise", req, &rpcwrapper.Response{}); err != nil {
		delete(s.initDone, contextID)
		return fmt.Errorf("Failed to send supervise command: context=%s error=%s", contextID, err)
	}

	return nil

}

// Unsupervise exported stops enforcing policy for the given IP.
func (s *ProxyInfo) Unsupervise(contextID string) error {

	delete(s.initDone, contextID)

	s.prochdl.KillProcess(contextID)

	return nil
}

// SetTargetNetworks sets the target networks in case of an  update
func (s *ProxyInfo) SetTargetNetworks(networks []string) error {
	for contextID, done := range s.initDone {
		if done {
			request := &rpcwrapper.Request{
				Payload: &rpcwrapper.InitSupervisorPayload{
					TriremeNetworks: networks,
					CaptureMethod:   rpcwrapper.IPTables,
				},
			}

			if err := s.rpchdl.RemoteCall(contextID, "Server.InitSupervisor", request, &rpcwrapper.Response{}); err != nil {
				return fmt.Errorf("Failed to initialize remote supervisor: context=%s error=%s", contextID, err)
			}
		}
	}

	return nil
}

// Start This method does nothing and is implemented for completeness
// THe work done is done in the InitRemoteSupervisor method in the remote enforcer
func (s *ProxyInfo) Start() error {

	return nil
}

//Stop This method does nothing
func (s *ProxyInfo) Stop() error {
	for c := range s.initDone {
		s.Unsupervise(c) // nolint
	}
	return nil
}

// NewProxySupervisor creates a new IptablesSupervisor launcher
func NewProxySupervisor(collector collector.EventCollector, enforcer enforcer.PolicyEnforcer, rpchdl rpcwrapper.RPCClient) (*ProxyInfo, error) {

	if collector == nil {
		return nil, fmt.Errorf("Collector cannot be nil")
	}
	if enforcer == nil {
		return nil, fmt.Errorf("Enforcer cannot be nil")
	}

	s := &ProxyInfo{
		versionTracker:    cache.NewCache(),
		collector:         collector,
		networkQueues:     strconv.Itoa(int(enforcer.GetFilterQueue().NetworkQueue)) + ":" + strconv.Itoa(int(enforcer.GetFilterQueue().NetworkQueue+enforcer.GetFilterQueue().NumberOfNetworkQueues-1)),
		applicationQueues: strconv.Itoa(int(enforcer.GetFilterQueue().ApplicationQueue)) + ":" + strconv.Itoa(int(enforcer.GetFilterQueue().ApplicationQueue+enforcer.GetFilterQueue().NumberOfApplicationQueues-1)),
		prochdl:           processmon.GetProcessManagerHdl(),
		rpchdl:            rpchdl,
		initDone:          make(map[string]bool),
		ExcludedIPs:       []string{},
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

	if err := s.rpchdl.RemoteCall(contextID, "Server.InitSupervisor", request, &rpcwrapper.Response{}); err != nil {
		return fmt.Errorf("Failed to initialize remote supervisor: context=%s error=%s", contextID, err)
	}

	s.initDone[contextID] = true

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
			return fmt.Errorf("Failed to add excluded IP list: context=%s error=%s", contextID, err)
		}
	}
	return nil
}
