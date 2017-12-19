package remoteenforcer

import (
	"github.com/aporeto-inc/trireme-lib/enforcer/packetprocessor"
	"github.com/aporeto-inc/trireme-lib/enforcer/policyenforcer"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/internal/remoteenforcer/internal/statsclient"
	"github.com/aporeto-inc/trireme-lib/internal/remoteenforcer/internal/statscollector"
	"github.com/aporeto-inc/trireme-lib/internal/supervisor"
)

// RemoteEnforcer : This is the structure for maintaining state required by the
// remote enforcer.
// It is a cache of variables passed by th controller to the remote enforcer and
// other handles required by the remote enforcer to talk to the external processes
//
// Why is this public when all members are private ? For golang RPC server requirements
type RemoteEnforcer struct {
	rpcSecret      string
	rpcChannel     string
	rpcHandle      rpcwrapper.RPCServer
	collector      statscollector.Collector
	statsClient    statsclient.StatsClient
	procMountPoint string
	enforcer       policyenforcer.Enforcer
	supervisor     supervisor.Supervisor
	service        packetprocessor.PacketProcessor
	secrets        secrets.Secrets
}
