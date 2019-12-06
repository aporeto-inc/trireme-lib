// +build !linux

package remoteenforcer

import (
	"context"

	"github.com/blang/semver"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/dnsreportclient"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/tokenissuer"
	"go.aporeto.io/trireme-lib/policy"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor"
	"go.aporeto.io/trireme-lib/controller/pkg/packetprocessor"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/counterclient"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/debugclient"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/statsclient"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/statscollector"
	"go.uber.org/zap"
)

var (
	createEnforcer = enforcer.New

	createSupervisor = supervisor.NewSupervisor
)

// newServer is a fake implementation for building on darwin.
func newRemoteEnforcer(
	ctx context.Context,
	cancel context.CancelFunc,
	service packetprocessor.PacketProcessor,
	rpcHandle rpcwrapper.RPCServer,
	secret string,
	statsClient statsclient.StatsClient,
	collector statscollector.Collector,
	debugClient debugclient.DebugClient,
	counterClient counterclient.CounterClient,
	dnsReportClient dnsreportclient.DNSReportClient,
	tokenIssuer tokenissuer.TokenClient,
	zapConfig zap.Config,
	enforcerType policy.EnforcerType,
) (*RemoteEnforcer, error) {
	return nil, nil
}

// LaunchRemoteEnforcer is a fake implementation for building on darwin.
func LaunchRemoteEnforcer(service packetprocessor.PacketProcessor, zapConfig zap.Config, agentVersion semver.Version) error {
	return nil
}

// InitEnforcer is a function called from the controller using RPC. It intializes data structure required by the
// remote enforcer
func (s *RemoteEnforcer) InitEnforcer(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

// Enforce this method calls the enforce method on the enforcer created during initenforcer
func (s *RemoteEnforcer) Enforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

// Unenforce this method calls the unenforce method on the enforcer created from initenforcer
func (s *RemoteEnforcer) Unenforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

// EnforcerExit this method is called when  we received a killrpocess message from the controller
// This allows a graceful exit of the enforcer
func (s *RemoteEnforcer) EnforcerExit(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

// EnableDatapathPacketTracing enable nfq datapath packet tracing
func (s *RemoteEnforcer) EnableDatapathPacketTracing(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

// EnableIPTablesPacketTracing enables iptables trace packet tracing
func (s *RemoteEnforcer) EnableIPTablesPacketTracing(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

func (s *RemoteEnforcer) cleanup() {
	return
}
