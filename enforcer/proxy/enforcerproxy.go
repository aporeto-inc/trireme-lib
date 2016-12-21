// Package enforcerproxy :: This is the implementation of the RPC client
// It implementes the interface of Trireme Enforcer and forwards these
// requests to the actual remote enforcer instead of implementing locally
package enforcerproxy

import (
	"errors"
	"fmt"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/remote/launch"
)

//keyPEM is a private interface required by the enforcerlauncher to expose method not exposed by the
//PolicyEnforcer interface
type keyPEM interface {
	AuthPEM() []byte
	TransmittedPEM() []byte
	EncodingPEM() []byte
}

//ErrFailedtoLaunch exported
var ErrFailedtoLaunch = errors.New("Failed to Launch")

//ErrExpectedEnforcer exported
var ErrExpectedEnforcer = errors.New("Process was not launched")

// ErrEnforceFailed exported
var ErrEnforceFailed = errors.New("Failed to enforce rules")

// ErrInitFailed exported
var ErrInitFailed = errors.New("Failed remote Init")

//proxyInfo is the struct used to hold state about active enforcers in the system
type proxyInfo struct {
	MutualAuth  bool
	Secrets     tokens.Secrets
	serverID    string
	validity    time.Duration
	prochdl     ProcessMon.ProcessManager
	rpchdl      rpcwrapper.RPCClient
	initDone    map[string]bool
	filterQueue *enforcer.FilterQueue
}

//InitRemoteEnforcer method makes a RPC call to the remote enforcer
func (s *proxyInfo) InitRemoteEnforcer(contextID string) error {

	resp := &rpcwrapper.Response{}
	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.InitRequestPayload{
			FqConfig:   s.filterQueue,
			MutualAuth: s.MutualAuth,
			Validity:   s.validity,
			SecretType: s.Secrets.Type(),
			ServerID:   s.serverID,
			CAPEM:      s.Secrets.(keyPEM).AuthPEM(),
			PublicPEM:  s.Secrets.(keyPEM).TransmittedPEM(),
			PrivatePEM: s.Secrets.(keyPEM).EncodingPEM(),
		},
	}

	if err := s.rpchdl.RemoteCall(contextID, "Server.InitEnforcer", request, resp); err != nil {
		log.WithFields(log.Fields{
			"package": "enforcerproxy",
		}).Debug("Failed to initialize enforcer")
		return fmt.Errorf("Failed ot initialize remote enforcer")
	}

	s.initDone[contextID] = true

	return nil
}

//Enforcer: Enforce method makes a RPC call for the remote enforcer enforce emthod
func (s *proxyInfo) Enforce(contextID string, puInfo *policy.PUInfo) error {

	log.WithFields(log.Fields{
		"package": "enforcerproxy",
		"pid":     puInfo.Runtime.Pid(),
	}).Info("PID of container")

	err := s.prochdl.LaunchProcess(contextID, puInfo.Runtime.Pid(), s.rpchdl)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{"package": "enforcerproxy",
		"contexID":      contextID,
		"Lauch Process": err,
	}).Info("Called enforce and launched process")

	if _, ok := s.initDone[contextID]; !ok {
		if err = s.InitRemoteEnforcer(contextID); err != nil {
			return err
		}

	}

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.EnforcePayload{
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
		},
	}

	err = s.rpchdl.RemoteCall(contextID, "Server.Enforce", request, &rpcwrapper.Response{})
	if err != nil {
		log.WithFields(log.Fields{
			"package": "remenforcer",
			"error":   err,
		}).Fatal("Failed to Enforce remote enforcer")
		return ErrEnforceFailed
	}

	return nil
}

// Unenforce stops enforcing policy for the given contexID.
func (s *proxyInfo) Unenforce(contextID string) error {

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.UnEnforcePayload{
			ContextID: contextID,
		},
	}

	err := s.rpchdl.RemoteCall(contextID, "Server.Unenforce", request, &rpcwrapper.Response{})
	if err != nil {
		log.WithFields(log.Fields{
			"package": "remenforcer",
			"error":   err,
		}).Fatal("Failed to Enforce remote enforcer")
		return ErrEnforceFailed
	}

	delete(s.initDone, contextID)

	if s.prochdl.GetExitStatus(contextID) == false {
		s.prochdl.SetExitStatus(contextID, true)
	} else {
		s.prochdl.KillProcess(contextID)
	}

	return nil
}

// GetFilterQueue returns the current FilterQueueConfig.
func (s *proxyInfo) GetFilterQueue() *enforcer.FilterQueue {

	fqConfig := &enforcer.FilterQueue{
		NetworkQueue:              enforcer.DefaultNetworkQueue,
		NetworkQueueSize:          enforcer.DefaultQueueSize,
		NumberOfNetworkQueues:     enforcer.DefaultNumberOfQueues,
		ApplicationQueue:          enforcer.DefaultApplicationQueue,
		ApplicationQueueSize:      enforcer.DefaultQueueSize,
		NumberOfApplicationQueues: enforcer.DefaultNumberOfQueues,
		MarkValue:                 enforcer.DefaultMarkValue,
	}
	return fqConfig
}

// Start starts the the remote enforcer proxy.
func (s *proxyInfo) Start() error {
	return nil
}

// Stop stops the remote enforcer.
func (s *proxyInfo) Stop() error {
	return nil
}

//NewProxyEnforcer creates a new proxy to remote enforcers
func NewProxyEnforcer(mutualAuth bool,
	filterQueue *enforcer.FilterQueue,
	collector collector.EventCollector,
	service enforcer.PacketProcessor,
	secrets tokens.Secrets,
	serverID string,
	validity time.Duration,
	rpchdl rpcwrapper.RPCClient,
) enforcer.PolicyEnforcer {

	proxydata := &proxyInfo{
		MutualAuth:  mutualAuth,
		Secrets:     secrets,
		serverID:    serverID,
		validity:    validity,
		prochdl:     ProcessMon.GetProcessMonHdl(),
		rpchdl:      rpchdl,
		initDone:    make(map[string]bool),
		filterQueue: filterQueue,
	}
	log.WithFields(log.Fields{
		"package": "remenforcer",
		"method":  "NewDataPathEnforcer",
	}).Info("Called NewDataPathEnforcer")

	statsServer := rpcwrapper.NewRPCWrapper()
	rpcServer := &StatsServer{rpchdl: statsServer, collector: collector}

	// Start hte server for statistics collection
	go statsServer.StartServer("unix", rpcwrapper.StatsChannel, rpcServer)

	return proxydata
}

// NewDefaultProxyEnforcer This is the default datapth method. THis is implemented to keep the interface consistent whether we are local or remote enforcer
func NewDefaultProxyEnforcer(serverID string,
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
	return NewProxyEnforcer(
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
		log.WithFields(log.Fields{"package": "enforcerproxy"}).Error("Message sender cannot be verified")
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
