// Package enforcerproxy :: This is the implementation of the RPC client
// It implements the interface of Trireme Enforcer and forwards these
// requests to the actual remote enforcer instead of implementing locally
package enforcerproxy

import (
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/crypto"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/processmon"
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

//ProxyInfo is the struct used to hold state about active enforcers in the system
type ProxyInfo struct {
	MutualAuth        bool
	Secrets           secrets.Secrets
	serverID          string
	validity          time.Duration
	prochdl           processmon.ProcessManager
	rpchdl            rpcwrapper.RPCClient
	initDone          map[string]bool
	filterQueue       *fqconfig.FilterQueue
	commandArg        string
	statsServerSecret string
	procMountPoint    string
}

//InitRemoteEnforcer method makes a RPC call to the remote enforcer
func (s *ProxyInfo) InitRemoteEnforcer(contextID string) error {

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

	if s.Secrets.Type() == secrets.PKICompactType {
		request.Payload.(*rpcwrapper.InitRequestPayload).Token = s.Secrets.TransmittedKey()
	}

	if err := s.rpchdl.RemoteCall(contextID, "Server.InitEnforcer", request, resp); err != nil {
		return fmt.Errorf("Failed to initialize remote enforcer: status %s, error: %s", resp.Status, err.Error())
	}

	s.initDone[contextID] = true

	return nil
}

//Enforce method makes a RPC call for the remote enforcer enforce emthod
func (s *ProxyInfo) Enforce(contextID string, puInfo *policy.PUInfo) error {

	zap.L().Debug("PID of container", zap.Int("pid", puInfo.Runtime.Pid()))

	err := s.prochdl.LaunchProcess(contextID, puInfo.Runtime.Pid(), s.rpchdl, s.commandArg, s.statsServerSecret, s.procMountPoint)
	if err != nil {
		return err
	}

	zap.L().Debug("Called enforce and launched process", zap.String("contextID", contextID))

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
			ApplicationACLs:  puInfo.Policy.ApplicationACLs(),
			NetworkACLs:      puInfo.Policy.NetworkACLs(),
			PolicyIPs:        puInfo.Policy.IPAddresses(),
			Annotations:      puInfo.Policy.Annotations(),
			Identity:         puInfo.Policy.Identity(),
			ReceiverRules:    puInfo.Policy.ReceiverRules(),
			TransmitterRules: puInfo.Policy.TransmitterRules(),
			TriremeNetworks:  puInfo.Policy.TriremeNetworks(),
			ExcludedNetworks: puInfo.Policy.ExcludedNetworks(),
		},
	}

	err = s.rpchdl.RemoteCall(contextID, "Server.Enforce", request, &rpcwrapper.Response{})
	if err != nil {
		//We can't talk to the enforcer. Kill it and restart it
		s.prochdl.KillProcess(contextID)
		zap.L().Error("Failed to Enforce remote enforcer", zap.Error(err))
		return ErrEnforceFailed
	}

	return nil
}

// Unenforce stops enforcing policy for the given contexID.
func (s *ProxyInfo) Unenforce(contextID string) error {

	delete(s.initDone, contextID)

	return nil
}

// GetFilterQueue returns the current FilterQueueConfig.
func (s *ProxyInfo) GetFilterQueue() *fqconfig.FilterQueue {
	return s.filterQueue
}

// Start starts the the remote enforcer proxy.
func (s *ProxyInfo) Start() error {
	return nil
}

// Stop stops the remote enforcer.
func (s *ProxyInfo) Stop() error {
	return nil
}

//NewProxyEnforcer creates a new proxy to remote enforcers
func NewProxyEnforcer(mutualAuth bool,
	filterQueue *fqconfig.FilterQueue,
	collector collector.EventCollector,
	service enforcer.PacketProcessor,
	secrets secrets.Secrets,
	serverID string,
	validity time.Duration,
	rpchdl rpcwrapper.RPCClient,
	cmdArg string,
	procMountPoint string,
) enforcer.PolicyEnforcer {
	statsServersecret, err := crypto.GenerateRandomString(32)

	if err != nil {
		// There is a very small chance of this happening we will log an error here.
		zap.L().Error("Failed to generate random secret for stats reporting.Falling back to static secret", zap.Error(err))
		// We will use current time as the secret
		statsServersecret = time.Now().String()
	}

	proxydata := &ProxyInfo{
		MutualAuth:        mutualAuth,
		Secrets:           secrets,
		serverID:          serverID,
		validity:          validity,
		prochdl:           processmon.GetProcessManagerHdl(),
		rpchdl:            rpchdl,
		initDone:          make(map[string]bool),
		filterQueue:       filterQueue,
		commandArg:        cmdArg,
		statsServerSecret: statsServersecret,
		procMountPoint:    procMountPoint,
	}

	zap.L().Debug("Called NewDataPathEnforcer")

	statsServer := rpcwrapper.NewRPCWrapper()
	rpcServer := &StatsServer{rpchdl: statsServer, collector: collector, secret: statsServersecret}

	// Start hte server for statistics collection
	go statsServer.StartServer("unix", rpcwrapper.StatsChannel, rpcServer) // nolint

	return proxydata
}

// NewDefaultProxyEnforcer This is the default datapth method. THis is implemented to keep the interface consistent whether we are local or remote enforcer
func NewDefaultProxyEnforcer(serverID string,
	collector collector.EventCollector,
	secrets secrets.Secrets,
	rpchdl rpcwrapper.RPCClient,
	procMountPoint string,
) enforcer.PolicyEnforcer {

	mutualAuthorization := false
	fqConfig := fqconfig.NewFilterQueueWithDefaults()

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
	)
}

//StatsServer This struct is a receiver for Statsserver and maintains a handle to the RPC StatsServer
type StatsServer struct {
	collector collector.EventCollector
	rpchdl    rpcwrapper.RPCServer
	secret    string
}

//GetStats  is the function called from the remoteenforcer when it has new flow events to publish
func (r *StatsServer) GetStats(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !r.rpchdl.ProcessMessage(&req, r.secret) {
		zap.L().Error("Message sender cannot be verified")
		return errors.New("Message sender cannot be verified")
	}

	payload := req.Payload.(rpcwrapper.StatsPayload)

	for _, record := range payload.Flows {
		r.collector.CollectFlowEvent(record)
	}

	return nil
}
