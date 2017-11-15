package remoteenforcer

import (
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme/internal/remoteenforcer/internal/statsclient"
	"github.com/aporeto-inc/trireme/internal/remoteenforcer/internal/statscollector"
	"github.com/aporeto-inc/trireme/supervisor"
)

// RemoteEnforcer : This is the structure for maintaining state required by the remote enforcer.
// It is cache of variables passed by th controller to the remote enforcer and other handles
// required by the remote enforcer to talk to the external processes
//
// Why is this public when all members are private ? For golang RPC server requirements
type RemoteEnforcer struct {
	rpcSecret      string
	rpcchannel     string
	rpchdl         rpcwrapper.RPCServer
	collector      statscollector.Collector
	statsclient    statsclient.StatsClient
	procMountPoint string
	enforcer       enforcer.PolicyEnforcer
	supervisor     supervisor.Supervisor
	service        enforcer.PacketProcessor
	secrets        secrets.Secrets
}
