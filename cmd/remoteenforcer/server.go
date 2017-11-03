package remoteenforcer

import (
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme/supervisor"
)

// Server : This is the structure for maintaining state required by the remote enforcer.
// It is cache of variables passed by th controller to the remote enforcer and other handles
// required by the remote enforcer to talk to the external processes
type Server struct {
	rpcSecret      string
	rpcchannel     string
	rpchdl         rpcwrapper.RPCServer
	statsclient    Stats
	procMountPoint string
	Enforcer       enforcer.PolicyEnforcer
	Supervisor     supervisor.Supervisor
	Service        enforcer.PacketProcessor
	secrets        secrets.Secrets
}
