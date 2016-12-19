//Package remenforcer  :: This is the implementation of the RPC client
//It implementes the interface PolicyEnforcer and forwards these requests to the actual enforcer
package remenforcer

import (
	"errors"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
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

//launcherstate is the struct used to hold state about active enforcers in the system
type launcherState struct {
	MutualAuth bool
	Secrets    tokens.Secrets
	serverID   string
	validity   time.Duration
	prochdl    ProcessMon.ProcessManager
	rpchdl     rpcwrapper.RPCClient
	initDone   map[string]bool
}

//InitRemoteEnforcer method makes a RPC call to the remote enforcer
func (s *launcherState) InitRemoteEnforcer(contextID string, puInfo *policy.PUInfo) error {

	payload := &rpcwrapper.InitRequestPayload{}
	request := &rpcwrapper.Request{}

	resp := &rpcwrapper.Response{}

	payload.MutualAuth = s.MutualAuth
	payload.Validity = s.validity
	pem := s.Secrets.(keyPEM)
	payload.SecretType = s.Secrets.Type()

	payload.PublicPEM = pem.TransmittedPEM()
	payload.PrivatePEM = pem.EncodingPEM()
	payload.CAPEM = pem.AuthPEM()

	payload.ContextID = contextID

	request.Payload = payload
	s.initDone[contextID] = true
	err := s.rpchdl.RemoteCall(contextID, "Server.InitEnforcer", request, resp)
	return err
}

//Enforcer: Enforce method makes a RPC call for the remote enforcer enforce emthod
func (s *launcherState) Enforce(contextID string, puInfo *policy.PUInfo) error {
	log.WithFields(log.Fields{"package": "enforcerLauncher",
		"pid": puInfo.Runtime.Pid(),
	}).Info("PID of container")
	err := s.prochdl.LaunchProcess(contextID, puInfo.Runtime.Pid(), s.rpchdl)
	if err != nil {
		return err
	}
	log.WithFields(log.Fields{"package": "enforcerLauncher",
		"contexID":      contextID,
		"Lauch Process": err,
	}).Info("Called enforce and launched process")
	if _, ok := s.initDone[contextID]; !ok {
		s.InitRemoteEnforcer(contextID, puInfo)
	}
	request := &rpcwrapper.Request{}

	enfResp := &rpcwrapper.Response{}
	enfReq := &rpcwrapper.EnforcePayload{}
	enfReq.ContextID = contextID
	enfReq.PuPolicy = puInfo.Policy
	request.Payload = enfReq

	err = s.rpchdl.RemoteCall(contextID, "Server.Enforce", request, enfResp)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcerLauncher",
			"error":   err,
		}).Fatal("Failed to Enforce remote enforcer")
		return ErrEnforceFailed
	}
	return nil
}

// Unenforce stops enforcing policy for the given contexID.
func (s *launcherState) Unenforce(contextID string) error {

	request := &rpcwrapper.Request{}
	payload := &rpcwrapper.UnEnforcePayload{}
	unenfresp := &rpcwrapper.Response{}
	payload.ContextID = contextID
	request.Payload = payload
	s.rpchdl.RemoteCall(contextID, "Server.Unenforce", request, unenfresp)
	delete(s.initDone, contextID)
	if s.prochdl.GetExitStatus(contextID) == false {
		s.prochdl.SetExitStatus(contextID, true)
	} else {
		s.prochdl.KillProcess(contextID)

	}
	//The interface forces this signature.
	//But in the remote enforcer case we will never fail
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

	return nil
}

// Stop stops the PolicyEnforcer.
func (s *launcherState) Stop() error {

	return nil
}

//NewDatapathEnforcer creates a new enforcer launcher
func NewDatapathEnforcer(mutualAuth bool,
	filterQueue *enforcer.FilterQueue,
	collector collector.EventCollector,
	service enforcer.PacketProcessor,
	secrets tokens.Secrets,
	serverID string,
	validity time.Duration,
	rpchdl rpcwrapper.RPCClient,
) enforcer.PolicyEnforcer {

	launcher := &launcherState{
		MutualAuth: mutualAuth,
		Secrets:    secrets,
		serverID:   serverID,
		validity:   validity,
		prochdl:    ProcessMon.GetProcessMonHdl(),
		rpchdl:     rpchdl,
		initDone:   make(map[string]bool),
	}
	log.WithFields(log.Fields{"package": "enforcerLauncher",
		"method": "NewDataPathEnforcer",
	}).Info("Called NewDataPathEnforcer")

	statsServer := rpcwrapper.NewRPCWrapper()
	rpcServer := &StatsServer{rpchdl: statsServer, collector: collector}
	go statsServer.StartServer("unix", rpcwrapper.StatsChannel, rpcServer)
	return launcher
}

//NewDefaultDatapathEnforcer This is the default datapth method. THis is implemented to keep the interface consistent whether we are local or remote enforcer
func NewDefaultDatapathEnforcer(serverID string,
	collector collector.EventCollector,
	secrets tokens.Secrets,
	rpchdl *rpcwrapper.RPCWrapper) enforcer.PolicyEnforcer {

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

//StatsServer This struct is a receiver for Statsserver and maintains a handle to the RPC StatsServer
type StatsServer struct {
	collector collector.EventCollector
	rpchdl    rpcwrapper.RPCServer
}

//GetStats  is the function called from the remoteenforcer when it has new flow events to publish
func (r *StatsServer) GetStats(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !r.rpchdl.ProcessMessage(&req) {
		log.WithFields(log.Fields{"package": "enforcerLauncher"}).Error("Message sender cannot be verified")
		return errors.New("Message sender cannot be verified")
	}
	payload := req.Payload.(rpcwrapper.StatsPayload)
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
