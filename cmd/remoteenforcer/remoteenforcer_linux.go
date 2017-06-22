// +build linux

package remoteenforcer

/*
#cgo CFLAGS: -Wall
#include <stdlib.h>
*/
import "C"

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/configurator"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer"
	_ "github.com/aporeto-inc/trireme/enforcer/utils/nsenter" // nolint
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"
)

const (
	envSocketPath     = "APORETO_ENV_SOCKET_PATH"
	envSecret         = "APORETO_ENV_SECRET"
	envProcMountPoint = "APORETO_ENV_PROC_MOUNTPOINT"
	nsErrorState      = "APORETO_ENV_NSENTER_ERROR_STATE"
	nsEnterLogs       = "APORETO_ENV_NSENTER_LOGS"
)

// Server : This is the structure for maintaining state required by the remote enforcer.
// It is cache of variables passed by th controller to the remote enforcer and other handles
// required by the remote enforcer to talk to the external processes
type Server struct {
	rpcSecret      string
	rpcchannel     string
	rpchdl         rpcwrapper.RPCServer
	statsclient    *StatsClient
	procMountPoint string
	Enforcer       enforcer.PolicyEnforcer
	Supervisor     supervisor.Supervisor
	Service        enforcer.PacketProcessor
	secrets        secrets.Secrets
}

var cmdLock sync.Mutex

// NewServer starts a new server
func NewServer(service enforcer.PacketProcessor, rpchdl rpcwrapper.RPCServer, rpcchan string, secret string) (*Server, error) {

	statsclient, err := NewStatsClient()
	if err != nil {
		return nil, err
	}
	procMountPoint := os.Getenv(envProcMountPoint)
	if len(procMountPoint) == 0 {
		procMountPoint = configurator.DefaultProcMountPoint
	}
	return &Server{
		Service:        service,
		rpcchannel:     rpcchan,
		rpcSecret:      secret,
		rpchdl:         rpchdl,
		procMountPoint: procMountPoint,
		statsclient:    statsclient,
	}, nil
}

// getCEnvVariable returns an environment variable set in the c context
func getCEnvVariable(name string) string {

	val := C.getenv(C.CString(name))
	if val == nil {
		return ""
	}
	return C.GoString(val)
}

// InitEnforcer is a function called from the controller using RPC. It intializes data structure required by the
// remote enforcer
func (s *Server) InitEnforcer(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	//Check if successfully switched namespace
	nsEnterState := getCEnvVariable(nsErrorState)
	nsEnterLogMsg := getCEnvVariable(nsEnterLogs)
	if len(nsEnterState) != 0 {
		zap.L().Error("Remote enforcer failed",
			zap.String("nsErr", nsEnterState),
			zap.String("nsLogs", nsEnterLogMsg),
		)
		resp.Status = (nsEnterState)
		return errors.New(resp.Status)
	}

	pid := strconv.Itoa(os.Getpid())
	netns, err := exec.Command("ip", "netns", "identify", pid).Output()
	if err != nil {
		zap.L().Error("Remote enforcer failed: unable to identify namespace",
			zap.String("nsErr", nsEnterState),
			zap.String("nsLogs", nsEnterLogMsg),
			zap.Error(err),
		)
		resp.Status = err.Error()
		//return errors.New(resp.Status)
	}

	netnsString := strings.TrimSpace(string(netns))
	if len(netnsString) == 0 {
		zap.L().Error("Remote enforcer failed: not running in a namespace",
			zap.String("nsErr", nsEnterState),
			zap.String("nsLogs", nsEnterLogMsg),
			zap.Error(err),
		)
		resp.Status = "Not running in a namespace"
		//return errors.New(resp.Status)
	}

	zap.L().Debug("Remote enforcer launched",
		zap.String("nsLogs", nsEnterLogMsg),
	)

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Init message authentication failed")
		return errors.New(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload := req.Payload.(rpcwrapper.InitRequestPayload)
	switch payload.SecretType {
	case secrets.PKIType:
		// PKI params
		zap.L().Info("Using PKI Secrets")
		s.secrets, err = secrets.NewPKISecrets(payload.PrivatePEM, payload.PublicPEM, payload.CAPEM, map[string]*ecdsa.PublicKey{})
		if err != nil {
			return fmt.Errorf("Failed to initialize secrets")
		}
		s.Enforcer = enforcer.New(
			payload.MutualAuth,
			payload.FqConfig,
			s.statsclient.collector,
			s.Service,
			s.secrets,
			payload.ServerID,
			payload.Validity,
			constants.RemoteContainer,
			s.procMountPoint,
		)
	case secrets.PSKType:
		// PSK params
		zap.L().Info("Using PSK Secrets")
		s.secrets = secrets.NewPSKSecrets(payload.PrivatePEM)
		s.Enforcer = enforcer.New(
			payload.MutualAuth,
			payload.FqConfig,
			s.statsclient.collector,
			s.Service,
			s.secrets,
			payload.ServerID,
			payload.Validity,
			constants.RemoteContainer,
			s.procMountPoint,
		)
	case secrets.PKICompactType:
		// Compact PKI Parameters
		zap.L().Info("Using PKI Compact Secrets")
		s.secrets, err = secrets.NewCompactPKI(payload.PrivatePEM, payload.PublicPEM, payload.CAPEM, payload.Token)
		if err != nil {
			return fmt.Errorf("Failed to initialize secrets")
		}
		s.Enforcer = enforcer.New(
			payload.MutualAuth,
			payload.FqConfig,
			s.statsclient.collector,
			s.Service,
			s.secrets,
			payload.ServerID,
			payload.Validity,
			constants.RemoteContainer,
			s.procMountPoint,
		)
	case secrets.PKINull:
		// Null Encryption
		zap.L().Info("Using Null Secrets")
		s.secrets, err = secrets.NewNullPKI(payload.PrivatePEM, payload.PublicPEM, payload.CAPEM)
		if err != nil {
			return fmt.Errorf("Failed to initialize secrets")
		}
		s.Enforcer = enforcer.New(
			payload.MutualAuth,
			payload.FqConfig,
			s.statsclient.collector,
			s.Service,
			s.secrets,
			payload.ServerID,
			payload.Validity,
			constants.RemoteContainer,
			s.procMountPoint,
		)
	}

	s.Enforcer.Start()

	s.statsclient.connectStatsClient()

	resp.Status = ""

	return nil
}

// InitSupervisor is a function called from the controller over RPC. It initializes data structure required by the supervisor
func (s *Server) InitSupervisor(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Supervisor Init Message Auth Failed")
		return errors.New(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload := req.Payload.(rpcwrapper.InitSupervisorPayload)
	if s.Supervisor == nil {
		switch payload.CaptureMethod {
		case rpcwrapper.IPSets:
			//TO DO
			return fmt.Errorf("IPSets not supported yet")
		default:
			supervisorHandle, err := supervisor.NewSupervisor(
				s.statsclient.collector,
				s.Enforcer,
				constants.RemoteContainer,
				constants.IPTables,
				payload.TriremeNetworks,
			)
			if err != nil {
				zap.L().Error("Failed to instantiate the iptables supervisor", zap.Error(err))
				return err
			}
			s.Supervisor = supervisorHandle
		}

		s.Supervisor.Start()
		if s.Service != nil {
			s.Service.Initialize(s.secrets, s.Enforcer.GetFilterQueue())
		}

	} else {
		s.Supervisor.SetTargetNetworks(payload.TriremeNetworks)
	}

	resp.Status = ""

	return nil
}

//Supervise This method calls the supervisor method on the supervisor created during initsupervisor
func (s *Server) Supervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Supervise Message Auth Failed")
		return errors.New(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload := req.Payload.(rpcwrapper.SuperviseRequestPayload)
	pupolicy := policy.NewPUPolicy(payload.ManagementID,
		payload.TriremeAction,
		payload.ApplicationACLs,
		payload.NetworkACLs,
		payload.TransmitterRules,
		payload.ReceiverRules,
		payload.Identity,
		payload.Annotations,
		payload.PolicyIPs,
		payload.TriremeNetworks,
		payload.ExcludedNetworks,
		nil)

	runtime := policy.NewPURuntimeWithDefaults()

	puInfo := policy.PUInfoFromPolicyAndRuntime(payload.ContextID, pupolicy, runtime)

	// TODO - Set PID to 1 - needed only for statistics
	puInfo.Runtime.SetPid(1)

	zap.L().Debug("Called Supervise Start in remote_enforcer")

	err := s.Supervisor.Supervise(payload.ContextID, puInfo)
	if err != nil {
		zap.L().Error("Unable to initialize supervisor",
			zap.String("ContextID", payload.ContextID),
			zap.Error(err),
		)
		resp.Status = err.Error()
		return err
	}

	return nil

}

//Unenforce this method calls the unenforce method on the enforcer created from initenforcer
func (s *Server) Unenforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Unenforce Message Auth Failed")
		return errors.New(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload := req.Payload.(rpcwrapper.UnEnforcePayload)
	return s.Enforcer.Unenforce(payload.ContextID)
}

//Unsupervise This method calls the unsupervise method on the supervisor created during initsupervisor
func (s *Server) Unsupervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Unsupervise Message Auth Failed")
		return errors.New(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload := req.Payload.(rpcwrapper.UnSupervisePayload)
	return s.Supervisor.Unsupervise(payload.ContextID)
}

//Enforce this method calls the enforce method on the enforcer created during initenforcer
func (s *Server) Enforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Enforce Message Auth Failed")
		return errors.New(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload := req.Payload.(rpcwrapper.EnforcePayload)

	pupolicy := policy.NewPUPolicy(payload.ManagementID,
		payload.TriremeAction,
		payload.ApplicationACLs,
		payload.NetworkACLs,
		payload.TransmitterRules,
		payload.ReceiverRules,
		payload.Identity,
		payload.Annotations,
		payload.PolicyIPs,
		payload.TriremeNetworks,
		payload.ExcludedNetworks,
		nil)

	runtime := policy.NewPURuntimeWithDefaults()
	puInfo := policy.PUInfoFromPolicyAndRuntime(payload.ContextID, pupolicy, runtime)
	if puInfo == nil {
		return fmt.Errorf("Unable to instantiate puInfo")
	}
	if s.Enforcer == nil {
		zap.L().Fatal("Enforcer not inited")
	}
	if err := s.Enforcer.Enforce(payload.ContextID, puInfo); err != nil {
		resp.Status = err.Error()
		return err
	}

	zap.L().Debug("Enforcer enabled", zap.String("contextID", payload.ContextID))

	resp.Status = ""

	return nil
}

// EnforcerExit this method is called when  we received a killrpocess message from the controller
// This allows a graceful exit of the enforcer
func (s *Server) EnforcerExit(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	cmdLock.Lock()
	defer cmdLock.Unlock()

	msgErrors := ""

	//Cleanup resources held in this namespace
	if s.Supervisor != nil {
		if err := s.Supervisor.Stop(); err != nil {
			msgErrors = msgErrors + "SuperVisor Error:" + err.Error() + "-"
		}
	}

	if s.Enforcer != nil {
		if err := s.Enforcer.Stop(); err != nil {
			msgErrors = msgErrors + "Enforcer Error:" + err.Error() + "-"
		}
	}

	if s.statsclient != nil {
		s.statsclient.Stop()
	}

	s.Supervisor = nil
	s.Enforcer = nil
	s.statsclient = nil

	if len(msgErrors) > 0 {
		return fmt.Errorf(msgErrors)
	}

	return nil
}

// LaunchRemoteEnforcer launches a remote enforcer
func LaunchRemoteEnforcer(service enforcer.PacketProcessor) error {

	namedPipe := os.Getenv(envSocketPath)

	secret := os.Getenv(envSecret)

	if len(secret) == 0 {
		os.Exit(-1)
	}

	flag := unix.SIGHUP

	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(flag), 0, 0, 0); err != nil {
		return fmt.Errorf("Unable to set termination process")
	}

	rpchdl := rpcwrapper.NewRPCServer()

	server, err := NewServer(service, rpchdl, namedPipe, secret)
	if err != nil {
		return err
	}

	go rpchdl.StartServer("unix", namedPipe, server)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	<-c

	server.EnforcerExit(rpcwrapper.Request{}, &rpcwrapper.Response{})

	return nil
}
