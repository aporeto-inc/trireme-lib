package supervisorLauncher

import (
	"fmt"
	"strconv"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpc_payloads"

	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/remote/launch"
	"github.com/aporeto-inc/trireme/supervisor"
	"github.com/aporeto-inc/trireme/supervisor/provider"
)

//RemoteSupervisorHandle exported
type RemoteSupervisorHandle struct {
	versionTracker    cache.DataStore
	ipt               provider.IptablesProvider
	collector         collector.EventCollector
	networkQueues     string
	applicationQueues string
	targetNetworks    []string
	ExcludedIP        []string
	prochdl           ProcessMon.ProcessManager
	rpchdl            rpcWrapper.RPCClient
	initDone          map[string]bool
}

//Supervise exported
func (s *RemoteSupervisorHandle) Supervise(contextID string, puInfo *policy.PUInfo) error {
	if _, ok := s.initDone[contextID]; !ok {
		err := s.InitRemoteSupervisor(contextID, puInfo)
		if err != nil {
			return err
		}
	}

	req := new(rpcWrapper.Request)
	response := new(rpcWrapper.Response)
	payload := new(rpcWrapper.SuperviseRequestPayload)
	payload.ContextID = contextID
	payload.PuPolicy = puInfo.Policy
	req.Payload = payload
	return s.rpchdl.RemoteCall(contextID, "Server.Supervise", req, response)

}

// Unsupervise exported stops enforcing policy for the given IP.
func (s *RemoteSupervisorHandle) Unsupervise(contextID string) error {
	request := new(rpcWrapper.Request)
	payload := new(rpcWrapper.UnSupervisePayload)
	unenfresp := new(rpcWrapper.Response)
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

//Start exported
func (s *RemoteSupervisorHandle) Start() error {
	return nil
}

//Stop exported
func (s *RemoteSupervisorHandle) Stop() error {
	return nil
}

//NewIPTablesSupervisor exported
func NewIPTablesSupervisor(collector collector.EventCollector, enforcer enforcer.PolicyEnforcer, iptablesProvider provider.IptablesProvider, targetNetworks []string, rpchdl rpcWrapper.RPCClient) (supervisor.Supervisor, error) {
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

//InitRemoteSupervisor exported
func (s *RemoteSupervisorHandle) InitRemoteSupervisor(contextID string, puInfo *policy.PUInfo) error {

	response := new(rpcWrapper.Response)
	request := new(rpcWrapper.Request)
	payload := new(rpcWrapper.InitSupervisorPayload)
	s.initDone[contextID] = true
	payload.NetworkQueues = s.networkQueues
	payload.ApplicationQueues = s.applicationQueues
	payload.TargetNetworks = s.targetNetworks
	request.Payload = payload
	return s.rpchdl.RemoteCall(contextID, "Server.InitSupervisor", request, response)

}

//AddExcludedIP exported
func (s *RemoteSupervisorHandle) AddExcludedIP(ip string) error {
	//This is unimplemented right now
	return nil
}

// RemoveExcludedIP removes the exception for the destion IP given in parameter.
func (s *RemoteSupervisorHandle) RemoveExcludedIP(ip string) error {
	//This is unimplemented right now
	return nil
}
