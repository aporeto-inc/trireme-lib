package supervisorLauncher

import (
	"fmt"
	"strconv"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/remote/launch"
	"github.com/aporeto-inc/trireme/supervisor"
	"github.com/aporeto-inc/trireme/utils/rpc_payloads"
)

//RemoteSupervisorHandle exported
type RemoteSupervisorHandle struct {
	versionTracker    cache.DataStore
	ipt               supervisor.IptablesProvider
	collector         collector.EventCollector
	networkQueues     string
	applicationQueues string
	targetNetworks    []string
	ExcludedIP        []string
}

//Supervise exported
func (s *RemoteSupervisorHandle) Supervise(contextID string, puInfo *policy.PUInfo) error {
	//Launched process
	//Initialize the RPC client

	err := s.InitRemoteSupervisor(contextID, puInfo)
	if err != nil {
		return err
	}

	response := new(rpcWrapper.SuperviseResponsePayload)
	payload := new(rpcWrapper.SuperviseRequestPayload)
	payload.ContextID = contextID
	payload.PuPolicy = puInfo.Policy
	client, _ := ProcessMon.GetRPCClient(contextID)
	err = client.Client.Call("Server.Supervise", payload, response)
	fmt.Println(err)
	return nil
}

// Unsupervise exported stops enforcing policy for the given IP.
func (s *RemoteSupervisorHandle) Unsupervise(contextID string) error {
	rpcClient, _ := ProcessMon.GetRPCClient(contextID)
	unenfreq := new(rpcWrapper.UnEnforcePayload)
	unenfresp := new(rpcWrapper.UnEnforceResponsePayload)
	unenfreq.ContextID = contextID
	rpcClient.Client.Call("Server.Unsupervise", unenfreq, unenfresp)
	if ProcessMon.GetExitStatus(contextID) == false {
		//Unsupervise not called yet
		ProcessMon.SetExitStatus(contextID, true)
	} else {
		ProcessMon.KillProcess(contextID)
		//We are coming here last
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
func NewIPTablesSupervisor(collector collector.EventCollector, enforcer enforcer.PolicyEnforcer, iptablesProvider supervisor.IptablesProvider, targetNetworks []string) (supervisor.Supervisor, error) {
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
	}

	s.ipt = iptablesProvider
	return s, nil

}

//InitRemoteSupervisor exported
func (s *RemoteSupervisorHandle) InitRemoteSupervisor(contextID string, puInfo *policy.PUInfo) error {

	response := new(rpcWrapper.Response)
	payload := new(rpcWrapper.InitSupervisorPayload)

	payload.NetworkQueues = s.networkQueues
	payload.ApplicationQueues = s.applicationQueues
	payload.TargetNetworks = s.targetNetworks
	client, _ := ProcessMon.GetRPCClient(contextID)
	return client.Client.Call("Server.InitSupervisor", payload, response)
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
