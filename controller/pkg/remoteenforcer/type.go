package remoteenforcer

import (
	"context"

	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme-lib/controller/internal/supervisor"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/packetprocessor"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/remoteenforcer/internal/statsclient"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/remoteenforcer/internal/statscollector"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/secrets"
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
	enforcer       enforcer.Enforcer
	supervisor     supervisor.Supervisor
	service        packetprocessor.PacketProcessor
	secrets        secrets.Secrets
	ctx            context.Context
	cancel         context.CancelFunc
}
