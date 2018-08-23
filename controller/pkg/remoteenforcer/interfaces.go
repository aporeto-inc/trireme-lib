package remoteenforcer

import (
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
)

const (
	// InitEnforcer is string for invoking RPC
	InitEnforcer = "RemoteEnforcer.InitEnforcer"
	// InitSupervisor is string for invoking RPC
	InitSupervisor = "RemoteEnforcer.InitSupervisor"
	//Supervise is string for invoking RPC
	Supervise = "RemoteEnforcer.Supervise"
	//Unenforce is string for invoking RPC
	Unenforce = "RemoteEnforcer.Unenforce"
	//Unsupervise is string for invoking RPC
	Unsupervise = "RemoteEnforcer.Unsupervise"
	//Enforce is string for invoking RPC
	Enforce = "RemoteEnforcer.Enforce"
	// EnforcerExit is string for invoking RPC
	EnforcerExit = "RemoteEnforcer.EnforcerExit"
	// UpdateSecrets is string for invoking updatesecrets RPC
	UpdateSecrets = "RemoteEnforcer.UpdateSecrets"
	// SetTargetNetworks is string for invoking SetTargetNetworks RPC
	SetTargetNetworks = "RemoteEnforcer.SetTargetNetworks"
)

// RemoteIntf is the interface implemented by the remote enforcer
type RemoteIntf interface {
	// InitEnforcer is a function called from the controller using RPC.
	// It intializes data structure required by the remote enforcer
	InitEnforcer(req rpcwrapper.Request, resp *rpcwrapper.Response) error

	// InitSupervisor is a function called from the controller over RPC. It initializes data structure required by the supervisor
	InitSupervisor(req rpcwrapper.Request, resp *rpcwrapper.Response) error

	//Supervise This method calls the supervisor method on the supervisor created during initsupervisor
	Supervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error

	//Unenforce this method calls the unenforce method on the enforcer created from initenforcer
	Unenforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error

	//Unsupervise This method calls the unsupervise method on the supervisor created during initsupervisor
	Unsupervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error

	//Enforce this method calls the enforce method on the enforcer created during initenforcer
	Enforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error

	// EnforcerExit this method is called when  we received a killrpocess message from the controller
	// This allows a graceful exit of the enforcer
	EnforcerExit(req rpcwrapper.Request, resp *rpcwrapper.Response) error
}
