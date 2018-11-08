// Package enforcerproxy :: This is the implementation of the RPC client
// It implements the interface of Trireme Enforcer and forwards these
// requests to the actual remote enforcer instead of implementing locally
package enforcerproxy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/processmon"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packetprocessor"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/crypto"
	"go.uber.org/zap"
)

// ProxyInfo is the struct used to hold state about active enforcers in the system
type ProxyInfo struct {
	MutualAuth             bool
	PacketLogs             bool
	Secrets                secrets.Secrets
	serverID               string
	validity               time.Duration
	prochdl                processmon.ProcessManager
	rpchdl                 rpcwrapper.RPCClient
	initDone               map[string]bool
	filterQueue            *fqconfig.FilterQueue
	commandArg             string
	statsServerSecret      string
	procMountPoint         string
	ExternalIPCacheTimeout time.Duration
	collector              collector.EventCollector
	targetNetworks         []string
	sync.RWMutex
}

// InitRemoteEnforcer method makes a RPC call to the remote enforcer
func (s *ProxyInfo) InitRemoteEnforcer(contextID string) error {

	resp := &rpcwrapper.Response{}

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.InitRequestPayload{
			FqConfig:               s.filterQueue,
			MutualAuth:             s.MutualAuth,
			Validity:               s.validity,
			ServerID:               s.serverID,
			ExternalIPCacheTimeout: s.ExternalIPCacheTimeout,
			PacketLogs:             s.PacketLogs,
			Secrets:                s.Secrets.PublicSecrets(),
			TargetNetworks:         s.targetNetworks,
		},
	}

	if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.InitEnforcer, request, resp); err != nil {
		return fmt.Errorf("failed to initialize remote enforcer: status: %s: %s", resp.Status, err)
	}

	if resp.Status != "" {
		zap.L().Error("received status while initializing the remote enforcer", zap.String("contextID", resp.Status))
	}

	s.Lock()
	s.initDone[contextID] = true
	s.Unlock()

	return nil
}

// UpdateSecrets updates the secrets used for signing communication between trireme instances
func (s *ProxyInfo) UpdateSecrets(token secrets.Secrets) error {
	s.Lock()
	s.Secrets = token
	s.Unlock()

	resp := &rpcwrapper.Response{}
	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.UpdateSecretsPayload{
			Secrets: s.Secrets.PublicSecrets(),
		},
	}

	for _, contextID := range s.rpchdl.ContextList() {
		if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.UpdateSecrets, request, resp); err != nil {
			return fmt.Errorf("Failed to update secrets. status %s: %s", resp.Status, err)
		}
	}

	return nil
}

// Enforce method makes a RPC call for the remote enforcer enforce method
func (s *ProxyInfo) Enforce(contextID string, puInfo *policy.PUInfo) error {
	err := s.prochdl.LaunchProcess(
		contextID,
		puInfo.Runtime.Pid(),
		puInfo.Runtime.NSPath(),
		s.rpchdl,
		s.commandArg,
		s.statsServerSecret,
		s.procMountPoint,
		puInfo.Runtime.Options().ProxyPort,
	)
	if err != nil {
		return err
	}

	zap.L().Debug("Called enforce and launched process", zap.String("contextID", contextID))

	s.Lock()
	_, ok := s.initDone[contextID]
	s.Unlock()
	if !ok {
		if err = s.InitRemoteEnforcer(contextID); err != nil {
			return err
		}
	}

	enforcerPayload := &rpcwrapper.EnforcePayload{
		ContextID: contextID,
		Policy:    puInfo.Policy.ToPublicPolicy(),
	}

	//Only the secrets need to be under lock. They can change async to the enforce call from Updatesecrets
	s.RLock()
	enforcerPayload.Secrets = s.Secrets.PublicSecrets()
	s.RUnlock()
	request := &rpcwrapper.Request{
		Payload: enforcerPayload,
	}

	err = s.rpchdl.RemoteCall(contextID, remoteenforcer.Enforce, request, &rpcwrapper.Response{})
	if err != nil {
		// We can't talk to the enforcer. Kill it and restart it
		s.Lock()
		delete(s.initDone, contextID)
		s.Unlock()
		s.prochdl.KillProcess(contextID)
		return fmt.Errorf("failed to send message to remote enforcer: %s", err)
	}

	return nil
}

// Unenforce stops enforcing policy for the given contextID.
func (s *ProxyInfo) Unenforce(contextID string) error {

	s.Lock()
	delete(s.initDone, contextID)
	s.Unlock()

	return nil
}

// SetTargetNetworks does the RPC call for SetTargetNetworks to the corresponding
// remote enforcers
func (s *ProxyInfo) SetTargetNetworks(networks []string) error {
	resp := &rpcwrapper.Response{}
	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.SetTargetNetworks{
			TargetNetworks: networks,
		},
	}

	for _, contextID := range s.rpchdl.ContextList() {
		if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.SetTargetNetworks, request, resp); err != nil {
			return fmt.Errorf("Failed to update secrets. status %s: %s", resp.Status, err)
		}
	}

	return nil
}

// GetFilterQueue returns the current FilterQueueConfig.
func (s *ProxyInfo) GetFilterQueue() *fqconfig.FilterQueue {
	return s.filterQueue
}

// Run starts the the remote enforcer proxy.
func (s *ProxyInfo) Run(ctx context.Context) error {

	statsServer := rpcwrapper.NewRPCWrapper()
	rpcServer := &StatsServer{rpchdl: statsServer, collector: s.collector, secret: s.statsServerSecret}

	// Start the server for statistics collection.
	go statsServer.StartServer(ctx, "unix", rpcwrapper.StatsChannel, rpcServer) // nolint

	return nil
}

// NewProxyEnforcer creates a new proxy to remote enforcers.
func NewProxyEnforcer(mutualAuth bool,
	filterQueue *fqconfig.FilterQueue,
	collector collector.EventCollector,
	service packetprocessor.PacketProcessor,
	secrets secrets.Secrets,
	serverID string,
	validity time.Duration,
	rpchdl rpcwrapper.RPCClient,
	cmdArg string,
	procMountPoint string,
	ExternalIPCacheTimeout time.Duration,
	packetLogs bool,
	targetNetworks []string,
	runtimeError chan *policy.RuntimeError,
) enforcer.Enforcer {

	return newProxyEnforcer(
		mutualAuth,
		filterQueue,
		collector,
		service,
		secrets,
		serverID,
		validity,
		rpchdl,
		cmdArg,
		nil,
		procMountPoint,
		ExternalIPCacheTimeout,
		packetLogs,
		targetNetworks,
		runtimeError,
	)
}

// newProxyEnforcer creates a new proxy to remote enforcers.
func newProxyEnforcer(mutualAuth bool,
	filterQueue *fqconfig.FilterQueue,
	collector collector.EventCollector,
	service packetprocessor.PacketProcessor,
	secrets secrets.Secrets,
	serverID string,
	validity time.Duration,
	rpchdl rpcwrapper.RPCClient,
	cmdArg string,
	processmonitor processmon.ProcessManager,
	procMountPoint string,
	ExternalIPCacheTimeout time.Duration,
	packetLogs bool,
	targetNetworks []string,
	runtimeError chan *policy.RuntimeError,
) enforcer.Enforcer {

	statsServersecret, err := crypto.GenerateRandomString(32)
	if err != nil {
		// There is a very small chance of this happening we will log an error here.
		zap.L().Error("Failed to generate random secret for stats reporting.Falling back to static secret", zap.Error(err))
		// We will use current time as the secret
		statsServersecret = time.Now().String()
	}

	if processmonitor == nil {
		processmonitor = processmon.GetProcessManagerHdl()
	}
	processmonitor.SetRuntimeErrorChannel(runtimeError)

	proxydata := &ProxyInfo{
		MutualAuth:             mutualAuth,
		Secrets:                secrets,
		serverID:               serverID,
		validity:               validity,
		prochdl:                processmonitor,
		rpchdl:                 rpchdl,
		initDone:               make(map[string]bool),
		filterQueue:            filterQueue,
		commandArg:             cmdArg,
		statsServerSecret:      statsServersecret,
		procMountPoint:         procMountPoint,
		ExternalIPCacheTimeout: ExternalIPCacheTimeout,
		PacketLogs:             packetLogs,
		collector:              collector,
		targetNetworks:         targetNetworks,
	}

	return proxydata
}

// NewDefaultProxyEnforcer This is the default datapth method. THis is implemented to keep the interface consistent whether we are local or remote enforcer.
func NewDefaultProxyEnforcer(serverID string,
	collector collector.EventCollector,
	secrets secrets.Secrets,
	rpchdl rpcwrapper.RPCClient,
	procMountPoint string,
	targetNetworks []string,
	runtimeError chan *policy.RuntimeError,
) enforcer.Enforcer {

	mutualAuthorization := false
	fqConfig := fqconfig.NewFilterQueueWithDefaults()
	defaultExternalIPCacheTimeout, err := time.ParseDuration(enforcerconstants.DefaultExternalIPTimeout)
	if err != nil {
		defaultExternalIPCacheTimeout = time.Second
	}
	defaultPacketLogs := false
	validity := time.Hour * 8760
	return NewProxyEnforcer(
		mutualAuthorization,
		fqConfig,
		collector,
		nil,
		secrets,
		serverID,
		validity,
		rpchdl,
		constants.DefaultRemoteArg,
		procMountPoint,
		defaultExternalIPCacheTimeout,
		defaultPacketLogs,
		targetNetworks,
		runtimeError,
	)
}

// StatsServer This struct is a receiver for Statsserver and maintains a handle to the RPC StatsServer.
type StatsServer struct {
	collector collector.EventCollector
	rpchdl    rpcwrapper.RPCServer
	secret    string
}

// GetStats is the function called from the remoteenforcer when it has new flow events to publish.
func (r *StatsServer) GetStats(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !r.rpchdl.ProcessMessage(&req, r.secret) {
		return errors.New("message sender cannot be verified")
	}

	payload := req.Payload.(rpcwrapper.StatsPayload)

	for _, record := range payload.Flows {
		r.collector.CollectFlowEvent(record)
	}

	for _, record := range payload.Users {
		r.collector.CollectUserEvent(record)
	}

	return nil
}
