// Package supervisorproxy package implements the supervisor interface and forwards the requests on this interface
// to a remote supervisor over an rpc call.
package supervisorproxy

import (
	"fmt"
	"strconv"

	log "github.com/Sirupsen/logrus"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"

	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/remote/launch"
	"github.com/aporeto-inc/trireme/supervisor"
)

//ProxyInfo is a struct used to store state for the remote launcher.
//it mirrors what is stored by the supervisor and also information to talk with the
// remote enforcer
type ProxyInfo struct {
	versionTracker    cache.DataStore
	collector         collector.EventCollector
	networkQueues     string
	applicationQueues string
	targetNetworks    []string
	ExcludedIP        []string
	prochdl           ProcessMon.ProcessManager
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
			IngressACLs:      puInfo.Policy.IngressACLs(),
			EgressACLs:       puInfo.Policy.EgressACLs(),
			PolicyIPs:        puInfo.Policy.IPAddresses(),
			Annotations:      puInfo.Policy.Annotations(),
			Identity:         puInfo.Policy.Identity(),
			ReceiverRules:    puInfo.Policy.ReceiverRules(),
			TransmitterRules: puInfo.Policy.TransmitterRules(),
			PuPolicy:         puInfo.Policy,
		},
	}

	if err := s.rpchdl.RemoteCall(contextID, "Server.Supervise", req, &rpcwrapper.Response{}); err != nil {
		log.WithFields(log.Fields{
			"package":   "remsupervisor",
			"contextID": contextID,
		}).Debug("Failed to initialize remote supervisor")
		delete(s.initDone, contextID)
		return err
	}

	return nil

}

// Unsupervise exported stops enforcing policy for the given IP.
func (s *ProxyInfo) Unsupervise(contextID string) error {

	delete(s.initDone, contextID)

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.UnSupervisePayload{
			ContextID: contextID,
		},
	}

	if err := s.rpchdl.RemoteCall(contextID, "Server.Unsupervise", request, &rpcwrapper.Response{}); err != nil {
		log.WithFields(log.Fields{
			"package":   "remsupervisor",
			"contextID": contextID,
		}).Debug("Failed to initialize remote supervisor")
		delete(s.initDone, contextID)
	}

	if s.prochdl.GetExitStatus(contextID) == false {
		//Unsupervise not called yet
		s.prochdl.SetExitStatus(contextID, true)
	} else {
		//We are coming here last
		s.prochdl.KillProcess(contextID)
	}

	return nil
}

//Start This method does nothing and is implemented for completeness
// THe work done is done in the InitRemoteSupervisor method in the remote enforcer
func (s *ProxyInfo) Start() error {

	return nil
}

//Stop This method does nothing
func (s *ProxyInfo) Stop() error {

	return nil
}

// NewProxySupervisor creates a new IptablesSupervisor launcher
func NewProxySupervisor(collector collector.EventCollector, enforcer enforcer.PolicyEnforcer, targetNetworks []string, rpchdl rpcwrapper.RPCClient) (supervisor.Supervisor, error) {

	if collector == nil {
		return nil, fmt.Errorf("Collector cannot be nil")
	}
	if enforcer == nil {
		return nil, fmt.Errorf("Enforcer cannot be nil")
	}
	if targetNetworks == nil {
		return nil, fmt.Errorf("TargetNetworks cannot be nil")
	}
	s := &ProxyInfo{
		versionTracker:    cache.NewCache(),
		targetNetworks:    targetNetworks,
		collector:         collector,
		networkQueues:     strconv.Itoa(int(enforcer.GetFilterQueue().NetworkQueue)) + ":" + strconv.Itoa(int(enforcer.GetFilterQueue().NetworkQueue+enforcer.GetFilterQueue().NumberOfNetworkQueues-1)),
		applicationQueues: strconv.Itoa(int(enforcer.GetFilterQueue().ApplicationQueue)) + ":" + strconv.Itoa(int(enforcer.GetFilterQueue().ApplicationQueue+enforcer.GetFilterQueue().NumberOfApplicationQueues-1)),
		prochdl:           ProcessMon.GetProcessMonHdl(),
		rpchdl:            rpchdl,
		initDone:          make(map[string]bool),
	}

	return s, nil

}

//InitRemoteSupervisor calls initsupervisor method on the remote
func (s *ProxyInfo) InitRemoteSupervisor(contextID string, puInfo *policy.PUInfo) error {

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.InitSupervisorPayload{
			CaptureMethod:  rpcwrapper.IPTables,
			TargetNetworks: s.targetNetworks,
		},
	}

	if err := s.rpchdl.RemoteCall(contextID, "Server.InitSupervisor", request, &rpcwrapper.Response{}); err != nil {
		log.WithFields(log.Fields{
			"package":   "remsupervisor",
			"contextID": contextID,
		}).Debug("Failed to initialize remote supervisor")
		return err
	}

	s.initDone[contextID] = true

	return nil

}

//AddExcludedIP call addexcluded ip on the remote supervisor
func (s *ProxyInfo) AddExcludedIP(ip string) error {

	//This is unimplemented right now
	return nil
}

// RemoveExcludedIP removes the exception for the destion IP given in parameter.
func (s *ProxyInfo) RemoveExcludedIP(ip string) error {

	//This is unimplemented right now
	return nil
}
