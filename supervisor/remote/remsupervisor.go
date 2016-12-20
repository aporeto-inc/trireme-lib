//remsupervisor package implements the supervisor interface and forwards the requests on this interface
// to the remote enforcer
package remsupervisor

import (
	"fmt"
	"strconv"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"

	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/remote/launch"
	"github.com/aporeto-inc/trireme/supervisor"
	"github.com/aporeto-inc/trireme/supervisor/iptablesutils"
)

//RemoteSupervisorHandle is a struct used to store state for the remote launcher.
//it mirrors what is stored by the supervisor and also information to talk with the
// remote enforcer
type RemoteSupervisorHandle struct {
	versionTracker    cache.DataStore
	ipt               iptablesutils.IptableUtils
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
func (s *RemoteSupervisorHandle) Supervise(contextID string, puInfo *policy.PUInfo) error {

	if _, ok := s.initDone[contextID]; !ok {
		err := s.InitRemoteSupervisor(contextID, puInfo)
		if err != nil {
			return err
		}
	}

	req := &rpcwrapper.Request{}
	response := &rpcwrapper.Response{}
	payload := &rpcwrapper.SuperviseRequestPayload{}
	payload.ContextID = contextID
	payload.ManagementID = puInfo.Policy.ManagementID
	payload.TriremeAction = puInfo.Policy.TriremeAction
	payload.IngressACLs = puInfo.Policy.IngressACLs()
	payload.EgressACLs = puInfo.Policy.EgressACLs()
	payload.PolicyIPs = puInfo.Policy.IPAddresses()
	payload.Annotations = puInfo.Policy.Annotations()
	payload.Identity = puInfo.Policy.Identity()
	payload.ReceiverRules = puInfo.Policy.ReceiverRules()
	payload.TransmitterRules = puInfo.Policy.TransmitterRules()
	payload.PuPolicy = puInfo.Policy
	req.Payload = payload
	return s.rpchdl.RemoteCall(contextID, "Server.Supervise", req, response)

}

// Unsupervise exported stops enforcing policy for the given IP.
func (s *RemoteSupervisorHandle) Unsupervise(contextID string) error {

	request := &rpcwrapper.Request{}
	payload := &rpcwrapper.UnSupervisePayload{}
	unenfresp := &rpcwrapper.Response{}
	payload.ContextID = contextID
	request.Payload = payload
	s.rpchdl.RemoteCall(contextID, "Server.Unsupervise", request, unenfresp)
	delete(s.initDone, contextID)
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
func (s *RemoteSupervisorHandle) Start() error {

	return nil
}

//Stop This method does nothing
func (s *RemoteSupervisorHandle) Stop() error {

	return nil
}

//NewIPTablesSupervisor creates a new IptablesSupervisor launcher
func NewIPTablesSupervisor(collector collector.EventCollector, enforcer enforcer.PolicyEnforcer, iptablesProvider iptablesutils.IptableUtils, targetNetworks []string, rpchdl rpcwrapper.RPCClient) (supervisor.Supervisor, error) {

	if collector == nil {
		return nil, fmt.Errorf("Collector cannot be nil")
	}
	if enforcer == nil {
		return nil, fmt.Errorf("Enforcer cannot be nil")
	}
	if targetNetworks == nil {
		return nil, fmt.Errorf("TargetNetworks cannot be nil")
	}
	s := &RemoteSupervisorHandle{
		versionTracker:    cache.NewCache(nil),
		targetNetworks:    targetNetworks,
		collector:         collector,
		networkQueues:     strconv.Itoa(int(enforcer.GetFilterQueue().NetworkQueue)) + ":" + strconv.Itoa(int(enforcer.GetFilterQueue().NetworkQueue+enforcer.GetFilterQueue().NumberOfNetworkQueues-1)),
		applicationQueues: strconv.Itoa(int(enforcer.GetFilterQueue().ApplicationQueue)) + ":" + strconv.Itoa(int(enforcer.GetFilterQueue().ApplicationQueue+enforcer.GetFilterQueue().NumberOfApplicationQueues-1)),
		prochdl:           ProcessMon.GetProcessMonHdl(),
		rpchdl:            rpchdl,
		initDone:          make(map[string]bool),
	}

	s.ipt = iptablesProvider
	return s, nil

}

//InitRemoteSupervisor calls initsupervisor method on the remoteneforcer
func (s *RemoteSupervisorHandle) InitRemoteSupervisor(contextID string, puInfo *policy.PUInfo) error {

	response := &rpcwrapper.Response{}
	request := &rpcwrapper.Request{}
	payload := &rpcwrapper.InitSupervisorPayload{}
	s.initDone[contextID] = true
	payload.NetworkQueues = s.networkQueues
	payload.ApplicationQueues = s.applicationQueues
	payload.TargetNetworks = s.targetNetworks
	request.Payload = payload
	return s.rpchdl.RemoteCall(contextID, "Server.InitSupervisor", request, response)

}

//AddExcludedIP call addexcluded ip on the remote supervisor
func (s *RemoteSupervisorHandle) AddExcludedIP(ip string) error {

	//This is unimplemented right now
	return nil
}

// RemoveExcludedIP removes the exception for the destion IP given in parameter.
func (s *RemoteSupervisorHandle) RemoveExcludedIP(ip string) error {

	//This is unimplemented right now
	return nil
}
