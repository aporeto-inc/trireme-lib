// +build !linux

package remoteenforcer

import (
	"context"

	"github.com/blang/semver"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/remoteenforcer/internal/client"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/remoteenforcer/internal/tokenissuer"
	"go.aporeto.io/enforcerd/trireme-lib/policy"

	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/supervisor"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/remoteenforcer/internal/statscollector"
)

// nolint:unused // seem to be used by the test
var (
	createEnforcer   = enforcer.New
	createSupervisor = supervisor.NewSupervisor
)

// newRemoteEnforcer starts a new server
func newRemoteEnforcer(
	ctx context.Context,
	rpcHandle rpcwrapper.RPCServer,
	secret string,
	statsClient client.Reporter,
	collector statscollector.Collector,
	reportsClient client.Reporter,
	tokenIssuer tokenissuer.TokenClient,
	logLevel string,
	logFormat string,
	logID string,
	numQueues int,
	enforcerType policy.EnforcerType,
	agentVersion semver.Version,
) (*RemoteEnforcer, error) {
	return nil, nil
}

// LaunchRemoteEnforcer is a fake implementation for building on darwin.
func LaunchRemoteEnforcer(ctx context.Context, logLevel, logFormat, logID string, numQueues int, agentVersion semver.Version) error {
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
