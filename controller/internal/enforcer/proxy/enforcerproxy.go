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
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/processmon"
	"go.aporeto.io/trireme-lib/controller/pkg/env"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/crypto"
	"go.uber.org/zap"
)

// ProxyInfo is the struct used to hold state about active enforcers in the system
type ProxyInfo struct {
	mutualAuth             bool
	packetLogs             bool
	Secrets                secrets.Secrets
	serverID               string
	validity               time.Duration
	prochdl                processmon.ProcessManager
	rpchdl                 rpcwrapper.RPCClient
	filterQueue            *fqconfig.FilterQueue
	commandArg             string
	statsServerSecret      string
	procMountPoint         string
	ExternalIPCacheTimeout time.Duration
	collector              collector.EventCollector
	cfg                    *runtime.Configuration

	sync.RWMutex
}

// Enforce method makes a RPC call for the remote enforcer enforce method
func (s *ProxyInfo) Enforce(contextID string, puInfo *policy.PUInfo) error {

	initEnforcer, err := s.prochdl.LaunchRemoteEnforcer(
		contextID,
		puInfo.Runtime.Pid(),
		puInfo.Runtime.NSPath(),
		s.commandArg,
		s.statsServerSecret,
		s.procMountPoint,
	)
	if err != nil {
		return err
	}

	zap.L().Debug("Called enforce and launched process", zap.String("contextID", contextID))

	if initEnforcer {
		if err := s.initRemoteEnforcer(contextID); err != nil {
			s.prochdl.KillRemoteEnforcer(contextID, true) // nolint errcheck
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

	if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.Enforce, request, &rpcwrapper.Response{}); err != nil {
		s.prochdl.KillRemoteEnforcer(contextID, true) // nolint errcheck
		return fmt.Errorf("failed to send message to remote enforcer: %s", err)
	}

	return nil
}

// Unenforce stops enforcing policy for the given contextID.
func (s *ProxyInfo) Unenforce(contextID string) error {

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.UnEnforcePayload{
			ContextID: contextID,
		},
	}

	if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.Unenforce, request, &rpcwrapper.Response{}); err != nil {
		zap.L().Error("failed to send message to remote enforcer", zap.Error(err))
	}

	return s.prochdl.KillRemoteEnforcer(contextID, true)
}

// UpdateSecrets updates the secrets used for signing communication between trireme instances
func (s *ProxyInfo) UpdateSecrets(token secrets.Secrets) error {
	s.Lock()
	s.Secrets = token
	s.Unlock()

	var allErrors string

	resp := &rpcwrapper.Response{}
	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.UpdateSecretsPayload{
			Secrets: s.Secrets.PublicSecrets(),
		},
	}

	for _, contextID := range s.rpchdl.ContextList() {
		if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.UpdateSecrets, request, resp); err != nil {
			allErrors = allErrors + " contextID " + contextID + ":" + err.Error()
		}
	}

	if len(allErrors) > 0 {
		return fmt.Errorf("unable to update secrets for some remotes: %s", allErrors)
	}

	return nil
}

// CleanUp sends a cleanup command to all the remotes forcing them to exit and clean their state.
func (s *ProxyInfo) CleanUp() error {

	// request := &rpcwrapper.Request{}

	var allErrors string

	for _, contextID := range s.rpchdl.ContextList() {

		if err := s.prochdl.KillRemoteEnforcer(contextID, false); err != nil {
			allErrors = allErrors + " contextID:" + err.Error()
		}
	}

	if len(allErrors) > 0 {
		return fmt.Errorf("Remote enforcers failed: %s", allErrors)
	}

	return nil
}

// EnableDatapathPacketTracing enable nfq packet tracing in remote container
func (s *ProxyInfo) EnableDatapathPacketTracing(contextID string, direction packettracing.TracingDirection, interval time.Duration) error {

	resp := &rpcwrapper.Response{}

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.EnableDatapathPacketTracingPayLoad{
			Direction: direction,
			Interval:  interval,
			ContextID: contextID,
		},
	}

	if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.EnableDatapathPacketTracing, request, resp); err != nil {
		return fmt.Errorf("unable to enable datapath packet tracing %s -- %s", err, resp.Status)
	}

	return nil
}

// EnableIPTablesPacketTracing enable iptables tracing
func (s *ProxyInfo) EnableIPTablesPacketTracing(ctx context.Context, contextID string, interval time.Duration) error {

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.EnableIPTablesPacketTracingPayLoad{
			IPTablesPacketTracing: true,
			Interval:              interval,
			ContextID:             contextID,
		},
	}

	if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.EnableIPTablesPacketTracing, request, &rpcwrapper.Response{}); err != nil {
		return fmt.Errorf("Unable to enable iptables tracing for contextID %s: %s", contextID, err)
	}

	return nil
}

// SetTargetNetworks does the RPC call for SetTargetNetworks to the corresponding
// remote enforcers
func (s *ProxyInfo) SetTargetNetworks(cfg *runtime.Configuration) error {
	resp := &rpcwrapper.Response{}
	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.SetTargetNetworksPayload{
			Configuration: cfg,
		},
	}

	var allErrors string

	for _, contextID := range s.rpchdl.ContextList() {
		if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.SetTargetNetworks, request, resp); err != nil {
			allErrors = allErrors + " contextID " + contextID + ":" + err.Error()
		}
	}

	s.Lock()
	s.cfg = cfg
	s.Unlock()

	if len(allErrors) > 0 {
		return fmt.Errorf("Remote enforcers failed: %s", allErrors)
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
	rpcServer := &StatsServer{
		rpchdl:    statsServer,
		collector: s.collector,
		secret:    s.statsServerSecret,
	}

	// Start the server for statistics collection.
	go statsServer.StartServer(ctx, "unix", constants.StatsChannel, rpcServer) // nolint
	return nil
}

// initRemoteEnforcer method makes a RPC call to the remote enforcer
func (s *ProxyInfo) initRemoteEnforcer(contextID string) error {

	resp := &rpcwrapper.Response{}

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.InitRequestPayload{
			FqConfig:               s.filterQueue,
			MutualAuth:             s.mutualAuth,
			Validity:               s.validity,
			ServerID:               s.serverID,
			ExternalIPCacheTimeout: s.ExternalIPCacheTimeout,
			PacketLogs:             s.packetLogs,
			Secrets:                s.Secrets.PublicSecrets(),
			Configuration:          s.cfg,
		},
	}

	return s.rpchdl.RemoteCall(contextID, remoteenforcer.InitEnforcer, request, resp)
}

// NewProxyEnforcer creates a new proxy to remote enforcers.
func NewProxyEnforcer(
	mutualAuth bool,
	filterQueue *fqconfig.FilterQueue,
	collector collector.EventCollector,
	secrets secrets.Secrets,
	serverID string,
	validity time.Duration,
	cmdArg string,
	procMountPoint string,
	ExternalIPCacheTimeout time.Duration,
	packetLogs bool,
	cfg *runtime.Configuration,
	runtimeError chan *policy.RuntimeError,
	remoteParameters *env.RemoteParameters,
) enforcer.Enforcer {

	statsServersecret, err := crypto.GenerateRandomString(32)
	if err != nil {
		// There is a very small chance of this happening we will log an error here.
		zap.L().Error("Failed to generate random secret for stats reporting", zap.Error(err))
		// We will use current time as the secret
		statsServersecret = time.Now().String()
	}

	rpcClient := rpcwrapper.NewRPCWrapper()

	return &ProxyInfo{
		mutualAuth:             mutualAuth,
		Secrets:                secrets,
		serverID:               serverID,
		validity:               validity,
		prochdl:                processmon.New(context.Background(), remoteParameters, runtimeError, rpcClient),
		rpchdl:                 rpcClient,
		filterQueue:            filterQueue,
		commandArg:             cmdArg,
		statsServerSecret:      statsServersecret,
		procMountPoint:         procMountPoint,
		ExternalIPCacheTimeout: ExternalIPCacheTimeout,
		packetLogs:             packetLogs,
		collector:              collector,
		cfg:                    cfg,
	}
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

// PostPacketEvent is called from the remote to post multiple records from the remoteenforcer
func (r *StatsServer) PostPacketEvent(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	if !r.rpchdl.ProcessMessage(&req, r.secret) {
		return errors.New("message sender cannot be verified")
	}

	payload := req.Payload.(rpcwrapper.DebugPacketPayload)
	for _, record := range payload.PacketRecords {

		r.collector.CollectPacketEvent(record)
	}
	return nil
}
