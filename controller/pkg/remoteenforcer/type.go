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
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/client"
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
// The lint directives below are for non-linux compiles that use remoteenforcer_stub.go
type RemoteEnforcer struct {
	rpcSecret      string //nolint:structcheck,unused
	rpcHandle      rpcwrapper.RPCServer
	collector      statscollector.Collector //nolint:structcheck,unused
	statsClient    client.Reporter
	reportsClient  client.Reporter
	procMountPoint string
	enforcer       enforcer.Enforcer
	supervisor     supervisor.Supervisor
	service        packetprocessor.PacketProcessor
	secrets        secrets.Secrets //nolint:structcheck,unused
	ctx            context.Context
	cancel         context.CancelFunc
	exit           chan bool
	zapConfig      zap.Config              //nolint:structcheck,unused
	logLevel       constants.LogLevel      //nolint:structcheck,unused
	tokenIssuer    tokenissuer.TokenClient //nolint:structcheck,unused
	enforcerType   policy.EnforcerType     //nolint:structcheck,unused
	aclmanager     ipsetmanager.ACLManager //nolint:structcheck,unused
	agentVersion   semver.Version          //nolint:structcheck,unused
}
