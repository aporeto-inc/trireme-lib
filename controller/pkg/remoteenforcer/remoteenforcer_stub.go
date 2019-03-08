// +build !linux

package remoteenforcer

import (
	"context"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/pkg/packetprocessor"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/debugclient"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/statsclient"
)

// newServer is a fake implementation for building on darwin.
func newServer(ctx context.Context, cancel context.CancelFunc, service packetprocessor.PacketProcessor, rpchdl rpcwrapper.RPCServer, pcchan string, secret string, stats statsclient.StatsClient, debugClient debugclient.DebugClient) (RemoteIntf, error) {
	return nil, nil
}

// LaunchRemoteEnforcer is a fake implementation for building on darwin.
func LaunchRemoteEnforcer(service packetprocessor.PacketProcessor) error { return nil }

// InitEnforcer is a function called from the controller using RPC. It intializes data structure required by the
// remote enforcer
func (s *RemoteEnforcer) InitEnforcer(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

// InitSupervisor is a function called from the controller over RPC. It initializes data structure required by the supervisor
func (s *RemoteEnforcer) InitSupervisor(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

// Supervise This method calls the supervisor method on the supervisor created during initsupervisor
func (s *RemoteEnforcer) Supervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil

}

// Unenforce this method calls the unenforce method on the enforcer created from initenforcer
func (s *RemoteEnforcer) Unenforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

// Unsupervise This method calls the unsupervise method on the supervisor created during initsupervisor
func (s *RemoteEnforcer) Unsupervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

// Enforce this method calls the enforce method on the enforcer created during initenforcer
func (s *RemoteEnforcer) Enforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
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
