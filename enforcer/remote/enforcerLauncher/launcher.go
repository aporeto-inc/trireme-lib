//Package enforcerLauncher :: This is the implementation of the RPC client
//It implementes the interface PolicyEnforcer and forwards these requests to the actual enforcer
package enforcerLauncher

import (
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpc_payloads"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/remote/launch"
)

//ErrFailedtoLaunch exported
var ErrFailedtoLaunch = errors.New("Failed to Launch")

//ErrExpectedEnforcer exported
var ErrExpectedEnforcer = errors.New("Process was not launched")

// ErrEnforceFailed exported
var ErrEnforceFailed = errors.New("Failed to enforce rules")

// ErrInitFailed exported
var ErrInitFailed = errors.New("Failed remote Init")

type launcherState struct {
	MutualAuth bool
	Secrets    tokens.Secrets
	serverID   string
	validity   time.Duration
	prochdl    ProcessMon.ProcessManager
	rpchdl     rpcWrapper.RPCClient
}

func (s *launcherState) InitRemoteEnforcer(contextID string, puInfo *policy.PUInfo) error {
	payload := new(rpcWrapper.InitRequestPayload)
	request := new(rpcWrapper.Request)

	resp := new(rpcWrapper.Response)

	payload.MutualAuth = s.MutualAuth
	payload.Validity = s.validity
	pem := s.Secrets.(keyPEM)
	payload.SecretType = s.Secrets.Type()

	payload.PublicPEM = pem.TransmittedPEM()
	payload.PrivatePEM = pem.EncodingPEM()
	payload.CAPEM = pem.AuthPEM()

	payload.ContextID = contextID

	request.Payload = payload
	//gob.Register(rpcWrapper.InitRequestPayload{})
	err := s.rpchdl.RemoteCall(contextID, "Server.InitEnforcer", request, resp)
	if err != nil {
		fmt.Println(err)
	}
	if resp.Status != nil {
		fmt.Println(resp.Status)
		panic("Init Failed")
	}

	return nil

}
func (s *launcherState) Enforce(contextID string, puInfo *policy.PUInfo) error {
	stack = string(debug.Stack())
	log.WithFields(log.Fields{"stack": stack}).Info("Stack trace")
	err := s.prochdl.LaunchProcess(contextID, puInfo.Runtime.Pid(), s.rpchdl)
	if err != nil {
		return err
	}
	log.WithFields(log.Fields{"package": "enforcerLauncher", "contexID": contextID, "Lauch Process": err}).Info("Called enforce and launched process")
	s.InitRemoteEnforcer(contextID, puInfo)
	request := new(rpcWrapper.Request)

	enfResp := new(rpcWrapper.Response)
	enfReq := new(rpcWrapper.EnforcePayload)
	enfReq.ContextID = contextID
	enfReq.PuPolicy = puInfo.Policy
	request.Payload = enfReq

	err = s.rpchdl.RemoteCall(contextID, "Server.Enforce", request, enfResp)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcerLauncher",
			"error":   err}).Fatal("Failed to Enforce remote enforcer")
		return ErrEnforceFailed
	}
	return nil
}

// Unenforce stops enforcing policy for the given IP.
func (s *launcherState) Unenforce(contextID string) error {
	request := new(rpcWrapper.Request)
	payload := new(rpcWrapper.UnEnforcePayload)
	unenfresp := new(rpcWrapper.Response)
	payload.ContextID = contextID
	request.Payload = payload
	s.rpchdl.RemoteCall(contextID, "Server.Unenforce", request, unenfresp)
	if s.prochdl.GetExitStatus(contextID) == false {
		s.prochdl.SetExitStatus(contextID, true)
	} else {
		s.prochdl.KillProcess(contextID)
	}
	return nil
}

// GetFilterQueue returns the current FilterQueueConfig.
func (s *launcherState) GetFilterQueue() *enforcer.FilterQueue {
	fqConfig := &enforcer.FilterQueue{
		NetworkQueue:              enforcer.DefaultNetworkQueue,
		NetworkQueueSize:          enforcer.DefaultQueueSize,
		NumberOfNetworkQueues:     enforcer.DefaultNumberOfQueues,
		ApplicationQueue:          enforcer.DefaultApplicationQueue,
		ApplicationQueueSize:      enforcer.DefaultQueueSize,
		NumberOfApplicationQueues: enforcer.DefaultNumberOfQueues,
	}
	return fqConfig
}

// Start starts the PolicyEnforcer.
//This method on the client does not do anything.
//At this point no container has started so we don't know
//what namespace to launch the new container
func (s *launcherState) Start() error {
	fmt.Println("Called Start")
	return nil
}

// Stop stops the PolicyEnforcer.
func (s *launcherState) Stop() error {
	return nil
}

//NewDatapathEnforcer exported
func NewDatapathEnforcer(mutualAuth bool,
	filterQueue *enforcer.FilterQueue,
	collector collector.EventCollector,
	service enforcer.PacketProcessor,
	secrets tokens.Secrets,
	serverID string,
	validity time.Duration,
	rpchdl rpcWrapper.RPCClient,
) enforcer.PolicyEnforcer {
	launcher := &launcherState{
		MutualAuth: mutualAuth,
		Secrets:    secrets,
		serverID:   serverID,
		validity:   validity,
		prochdl:    ProcessMon.GetProcessMonHdl(),
		rpchdl:     rpchdl,
	}
	log.WithFields(log.Fields{"package": "enforcerLauncher", "method": "NewDataPathEnforcer"}).Info("Called NewDataPathEnforcer")
	rpcwrapper := rpcWrapper.NewRPCWrapper()
	rpcserver := &RPCSERVER{rpchdl: rpcwrapper, collector: collector}
	go rpcwrapper.StartServer("unix", rpcWrapper.StatsChannel, rpcserver)
	return launcher
}

//NewDefaultDatapathEnforcer exported
func NewDefaultDatapathEnforcer(serverID string,
	collector collector.EventCollector,
	secrets tokens.Secrets,
	rpchdl *rpcWrapper.RPCWrapper) enforcer.PolicyEnforcer {
	mutualAuthorization := false
	fqConfig := &enforcer.FilterQueue{
		NetworkQueue:              enforcer.DefaultNetworkQueue,
		NetworkQueueSize:          enforcer.DefaultQueueSize,
		NumberOfNetworkQueues:     enforcer.DefaultNumberOfQueues,
		ApplicationQueue:          enforcer.DefaultApplicationQueue,
		ApplicationQueueSize:      enforcer.DefaultQueueSize,
		NumberOfApplicationQueues: enforcer.DefaultNumberOfQueues,
	}

	validity := time.Hour * 8760
	return NewDatapathEnforcer(
		mutualAuthorization,
		fqConfig,
		collector,
		nil,
		secrets,
		serverID,
		validity,
		rpchdl)
}

type RPCSERVER struct {
	collector collector.EventCollector
	rpchdl    rpcWrapper.RPCServer
}

func (r *RPCSERVER) GetStats(req rpcWrapper.Request, resp *rpcWrapper.Response) error {
	if !r.rpchdl.ProcessMessage(&req) {
		log.WithFields(log.Fields{"package": "enforcerLauncher"}).Error("Message sender cannot be verified")
		return errors.New("Message sender cannot be verified")
	}
	payload := req.Payload.(rpcWrapper.StatsPayload)
	// var flowSlice []enforcer.StatsPayload
	// flowSlice = payload.Flows
	for _, flow := range payload.Flows {
		if r.collector != nil {
			r.collector.CollectFlowEvent(flow.ContextID,
				flow.Tags,
				flow.Action,
				flow.Mode,
				flow.Source,
				flow.Packet)
		}
	}
	return nil
}
