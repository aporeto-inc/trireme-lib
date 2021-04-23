// Package enforcerproxy :: This is the implementation of the RPC client
// It implements the interface of Trireme Enforcer and forwards these
// requests to the actual remote enforcer instead of implementing locally
package enforcerproxy

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/processmon"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/ebpf"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/env"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/remoteenforcer"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/controller/runtime"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/crypto"
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
	filterQueue            fqconfig.FilterQueue
	commandArg             string
	statsServerSecret      string
	procMountPoint         string
	ExternalIPCacheTimeout time.Duration
	collector              collector.EventCollector
	cfg                    *runtime.Configuration
	tokenIssuer            common.ServiceTokenIssuer
	binaryTokens           bool
	isBPFEnabled           bool
	ipv6Enabled            bool
	serviceMeshType        policy.ServiceMesh
	rpcServer              rpcwrapper.RPCServer
	iptablesLockfile       string
	sync.RWMutex
}

// Enforce method makes a RPC call for the remote enforcer enforce method
func (s *ProxyInfo) Enforce(ctx context.Context, contextID string, puInfo *policy.PUInfo) error {

	initEnforcer, err := s.prochdl.LaunchRemoteEnforcer(
		contextID,
		puInfo.Runtime.Pid(),
		puInfo.Runtime.NSPath(),
		s.commandArg,
		s.statsServerSecret,
		s.procMountPoint,
		puInfo.Policy.EnforcerType(),
	)

	if err != nil {
		return err
	}

	zap.L().Debug("Called enforce and launched remote process", zap.String("contextID", contextID),
		zap.String("enforcer type", puInfo.Policy.EnforcerType().String()),
		zap.String("serviceMeshType", puInfo.Runtime.ServiceMeshType.String()),
		zap.String("name", puInfo.Runtime.Name()))

	s.serviceMeshType = puInfo.Runtime.ServiceMeshType
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
	enforcerPayload.Secrets = s.Secrets.RPCSecrets()
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
func (s *ProxyInfo) Unenforce(ctx context.Context, contextID string) error {

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
			Secrets: s.Secrets.RPCSecrets(),
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

// SetLogLevel sets log level.
func (s *ProxyInfo) SetLogLevel(level constants.LogLevel) error {

	resp := &rpcwrapper.Response{}
	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.SetLogLevelPayload{
			Level: level,
		},
	}

	var allErrors string

	for _, contextID := range s.rpchdl.ContextList() {
		if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.SetLogLevel, request, resp); err != nil {
			allErrors = allErrors + " contextID " + contextID + ":" + err.Error()
		}
	}

	if len(allErrors) > 0 {
		return fmt.Errorf("unable to set log level: %s", allErrors)
	}

	return nil
}

// CleanUp sends a cleanup command to all the remotes forcing them to exit and clean their state.
func (s *ProxyInfo) CleanUp() error {
	var synch sync.Mutex
	var wg sync.WaitGroup

	contextList := s.rpchdl.ContextList()
	lenCids := len(contextList)

	if lenCids == 0 {
		return nil
	}

	zap.L().Info(strconv.Itoa(lenCids) + " remote enforcers waiting to be exited")

	var chs []chan string

	wg.Add(lenCids)
	for i := 0; i < 4; i++ {
		ch := make(chan string)
		chs = append(chs, ch)

		go func(ch chan string) {
			var cid string
			for {
				cid = <-ch
				if err := s.prochdl.KillRemoteEnforcer(cid, false); err != nil {
					zap.L().Error("enforcer with contextID "+cid+"failed to exit", zap.Error(err))
				}
				synch.Lock()
				lenCids = lenCids - 1
				m := 0
				switch {
				case lenCids >= 500:
					m = 250
				case lenCids >= 100:
					m = 100
				case lenCids >= 10:
					m = 10
				default:
					m = 1
				}

				if lenCids%m == 0 {
					zap.L().Info(strconv.Itoa(lenCids) + " remote enforcers waiting to be exited")
				}
				synch.Unlock()
				wg.Done()
			}
		}(ch)
	}

	for i, contextID := range contextList {
		chs[i%4] <- contextID
	}

	wg.Wait()
	zap.L().Info("All remote enforcers have exited...")

	return nil
}

// EnableDatapathPacketTracing enable nfq packet tracing in remote container
func (s *ProxyInfo) EnableDatapathPacketTracing(ctx context.Context, contextID string, direction packettracing.TracingDirection, interval time.Duration) error {

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

// GetBPFObject returns the bpf object
func (s *ProxyInfo) GetBPFObject() ebpf.BPFModule {
	return nil
}

// GetServiceMeshType is unimplemented in the envoy authorizer
func (s *ProxyInfo) GetServiceMeshType() policy.ServiceMesh {
	return policy.None
}

// GetFilterQueue returns the current FilterQueueConfig.
func (s *ProxyInfo) GetFilterQueue() fqconfig.FilterQueue {
	return s.filterQueue
}

// Run starts the the remote enforcer proxy.
func (s *ProxyInfo) Run(ctx context.Context) error {

	handler := &ProxyRPCServer{
		rpchdl:      s.rpcServer,
		collector:   s.collector,
		secret:      s.statsServerSecret,
		tokenIssuer: s.tokenIssuer,
		ctx:         ctx,
	}

	// Start the server for statistics collection.
	go s.rpcServer.StartServer(ctx, "unix", constants.StatsChannel, handler) // nolint

	return nil
}

// Ping runs ping from the given config.
func (s *ProxyInfo) Ping(ctx context.Context, contextID string, pingConfig *policy.PingConfig) error {

	resp := &rpcwrapper.Response{}

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.PingPayload{
			ContextID:  contextID,
			PingConfig: pingConfig,
		},
	}

	if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.Ping, request, resp); err != nil {
		return fmt.Errorf("unable to run ping %s -- %s", err, resp.Status)
	}

	return nil
}

// DebugCollect tells remote enforcer to start collecting debug info (pcap or misc commands).
// It does not wait for pcap collection to complete: the pid of tcpdump is returned.
// If another command is meant to be executed in remote enforcer, it should be quick, and its output is returned.
func (s *ProxyInfo) DebugCollect(ctx context.Context, contextID string, debugConfig *policy.DebugConfig) error {
	resp := &rpcwrapper.Response{}

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.DebugCollectPayload{
			ContextID:    contextID,
			PcapFilePath: debugConfig.FilePath,
			PcapFilter:   debugConfig.PcapFilter,
			CommandExec:  debugConfig.CommandExec,
		},
	}

	if err := s.rpchdl.RemoteCall(contextID, remoteenforcer.DebugCollect, request, resp); err != nil {
		return fmt.Errorf("unable to run debug collect %s -- %s", err, resp.Status)
	}

	responsePayload := resp.Payload.(rpcwrapper.DebugCollectResponsePayload)
	debugConfig.PID = responsePayload.PID
	debugConfig.CommandOutput = responsePayload.CommandOutput

	return nil
}

// initRemoteEnforcer method makes a RPC call to the remote enforcer
func (s *ProxyInfo) initRemoteEnforcer(contextID string) error {

	resp := &rpcwrapper.Response{}

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.InitRequestPayload{
			MutualAuth:             s.mutualAuth,
			Validity:               s.validity,
			ServerID:               s.serverID,
			ExternalIPCacheTimeout: s.ExternalIPCacheTimeout,
			PacketLogs:             s.packetLogs,
			Secrets:                s.Secrets.RPCSecrets(),
			Configuration:          s.cfg,
			BinaryTokens:           s.binaryTokens,
			IsBPFEnabled:           s.isBPFEnabled,
			ServiceMeshType:        s.serviceMeshType,
			IPv6Enabled:            s.ipv6Enabled,
			IPTablesLockfile:       s.iptablesLockfile,
		},
	}

	return s.rpchdl.RemoteCall(contextID, remoteenforcer.InitEnforcer, request, resp)
}

// NewProxyEnforcer creates a new proxy to remote enforcers.
func NewProxyEnforcer(
	ctx context.Context,
	mutualAuth bool,
	filterQueue fqconfig.FilterQueue,
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
	tokenIssuer common.ServiceTokenIssuer,
	isBPFEnabled bool,
	ipv6Enabled bool,
	iptablesLockfile string,
	rpcServer rpcwrapper.RPCServer,
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
		prochdl:                processmon.New(ctx, remoteParameters, runtimeError, rpcClient, filterQueue.GetNumQueues()),
		rpchdl:                 rpcClient,
		filterQueue:            filterQueue,
		commandArg:             cmdArg,
		statsServerSecret:      statsServersecret,
		procMountPoint:         procMountPoint,
		ExternalIPCacheTimeout: ExternalIPCacheTimeout,
		packetLogs:             packetLogs,
		collector:              collector,
		cfg:                    cfg,
		tokenIssuer:            tokenIssuer,
		isBPFEnabled:           isBPFEnabled,
		ipv6Enabled:            ipv6Enabled,
		iptablesLockfile:       iptablesLockfile,
		rpcServer:              rpcServer,
	}
}
