package remoteenforcer

import (
	"context"

	"github.com/blang/semver"
	"go.aporeto.io/trireme-lib/policy"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor"
	"go.aporeto.io/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/trireme-lib/controller/pkg/packetprocessor"
	reports "go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/reportsclient"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/statsclient"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/statscollector"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/tokenissuer"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.uber.org/zap"
)

// RemoteEnforcer : This is the structure for maintaining state required by the
// remote enforcer.
// It is a cache of variables passed by the controller to the remote enforcer and
// other handles required by the remote enforcer to talk to the external processes
//
// Why is this public when all members are private ? For golang RPC server requirements
type RemoteEnforcer struct {
	rpcSecret      string
	rpcHandle      rpcwrapper.RPCServer
	collector      statscollector.Collector
	statsClient    statsclient.StatsClient
	reportsClient  reports.ReportsClient
	procMountPoint string
	enforcer       enforcer.Enforcer
	supervisor     supervisor.Supervisor
	service        packetprocessor.PacketProcessor
	secrets        secrets.Secrets
	ctx            context.Context
	cancel         context.CancelFunc
	exit           chan bool
	zapConfig      zap.Config
	logLevel       constants.LogLevel
	tokenIssuer    tokenissuer.TokenClient
	enforcerType   policy.EnforcerType
	aclmanager     ipsetmanager.ACLManager
	agentVersion   semver.Version
}
