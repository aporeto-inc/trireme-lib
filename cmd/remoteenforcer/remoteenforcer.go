// +build !linux

package remoteenforcer

import (
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme/supervisor"
)

const (
	envSocketPath     = "APORETO_ENV_SOCKET_PATH"
	envSecret         = "APORETO_ENV_SECRET"
	envProcMountPoint = "APORETO_ENV_PROC_MOUNTPOINT"
	nsErrorState      = "APORETO_ENV_NSENTER_ERROR_STATE"
	nsEnterLogs       = "APORETO_ENV_NSENTER_LOGS"
)

// Server is a fake implementation for building on darwin.
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

// NewServer is a fake implementation for building on darwin.
func NewServer(service enforcer.PacketProcessor, rpchdl rpcwrapper.RPCServer, pcchan string, secret string, stats Stats) (*Server, error) {
	return nil, nil
}

// LaunchRemoteEnforcer is a fake implementation for building on darwin.
func LaunchRemoteEnforcer(service enforcer.PacketProcessor) error { return nil }

// getCEnvVariable returns an environment variable set in the c context
func getCEnvVariable(name string) string {
	return ""
}

// InitEnforcer is a function called from the controller using RPC. It intializes data structure required by the
// remote enforcer
func (s *Server) InitEnforcer(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

// InitSupervisor is a function called from the controller over RPC. It initializes data structure required by the supervisor
func (s *Server) InitSupervisor(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

//Supervise This method calls the supervisor method on the supervisor created during initsupervisor
func (s *Server) Supervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil

}

//Unenforce this method calls the unenforce method on the enforcer created from initenforcer
func (s *Server) Unenforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

//Unsupervise This method calls the unsupervise method on the supervisor created during initsupervisor
func (s *Server) Unsupervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

//Enforce this method calls the enforce method on the enforcer created during initenforcer
func (s *Server) Enforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}

// EnforcerExit this method is called when  we received a killrpocess message from the controller
// This allows a graceful exit of the enforcer
func (s *Server) EnforcerExit(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	return nil
}
