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
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer"
	_ "github.com/aporeto-inc/trireme/enforcer/utils/nsenter" // nolint
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
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
}

// NewServer starts a new server
func NewServer(service enforcer.PacketProcessor, rpchdl rpcwrapper.RPCServer, rpcchan string, secret string) (*Server, error) {

	statsclient, err := NewStatsClient()
	if err != nil {
		return nil, err
	}
	procMountPoint := os.Getenv(envProcMountPoint)
	if len(procMountPoint) == 0 {
		procMountPoint = "/proc"
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

		log.WithFields(log.Fields{
			"package": "remote_enforcer",
			"nsErr":   nsEnterState,
			"nsLogs":  nsEnterLogMsg,
		}).Error("Remote enforcer failed")
		resp.Status = (nsEnterState)
		return errors.New(resp.Status)
	}

	pid := strconv.Itoa(os.Getpid())
	netns, err := exec.Command("ip", "netns", "identify", pid).Output()
	if err != nil {
		log.WithFields(log.Fields{
			"package": "remote_enforcer",
			"nsErr":   nsEnterState,
			"nsLogs":  nsEnterLogMsg,
			"err":     err.Error(),
		}).Error("Remote enforcer failed - unable to identify namespace")
		resp.Status = err.Error()
		return errors.New(resp.Status)
	}

	netnsString := strings.TrimSpace(string(netns))
	if len(netnsString) == 0 {
		log.WithFields(log.Fields{
			"package": "remote_enforcer",
			"nsErr":   nsEnterState,
			"nsLogs":  nsEnterLogMsg,
		}).Error("Remote enforcer failed - not running in a namespace")
		resp.Status = "Not running in a namespace"
		return errors.New(resp.Status)
	}

	log.WithFields(log.Fields{
		"package": "remote_enforcer",
		"logs":    nsEnterLogMsg,
	}).Info("Remote enforcer launched")

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Init message authentication failed")
		return errors.New(resp.Status)
	}

	payload := req.Payload.(rpcwrapper.InitRequestPayload)
	if payload.SecretType == tokens.PKIType {
		//PKI params
		secrets := tokens.NewPKISecrets(payload.PrivatePEM, payload.PublicPEM, payload.CAPEM, map[string]*ecdsa.PublicKey{})
		s.Enforcer = enforcer.NewDatapathEnforcer(
			payload.MutualAuth,
			payload.FqConfig,
			s.statsclient.collector,
			s.Service,
			secrets,
			payload.ServerID,
			payload.Validity,
			constants.RemoteContainer,
			s.procMountPoint,
		)
	} else {
		//PSK params
		secrets := tokens.NewPSKSecrets(payload.PrivatePEM)
		s.Enforcer = enforcer.NewDatapathEnforcer(
			payload.MutualAuth,
			payload.FqConfig,
			s.statsclient.collector,
			s.Service,
			secrets,
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

	payload := req.Payload.(rpcwrapper.InitSupervisorPayload)
	switch payload.CaptureMethod {
	case rpcwrapper.IPSets:
		//TO DO
		return fmt.Errorf("IPSets not supported yet")
	default:

		supervisorHandle, err := supervisor.NewSupervisor(s.statsclient.collector,
			s.Enforcer,
			constants.RemoteContainer,
			constants.IPTables,
		)
		if err != nil {
			log.WithFields(log.Fields{
				"package": "remote_enforcer",
				"Error":   err.Error(),
			}).Error("Failed to instantiate the iptables supervisor")
			if err != nil {
				resp.Status = err.Error()
			}
			return err
		}
		s.Supervisor = supervisorHandle

	}

	s.Supervisor.Start()

	resp.Status = ""

	return nil
}

//Supervise This method calls the supervisor method on the supervisor created during initsupervisor
func (s *Server) Supervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Supervise Message Auth Failed")
		return errors.New(resp.Status)
	}

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

	log.WithFields(log.Fields{
		"package": "remote_enforcer",
		"method":  "Supervise",
	}).Info("Called Supervise Start in remote_enforcer")

	err := s.Supervisor.Supervise(payload.ContextID, puInfo)
	if err != nil {
		log.WithFields(log.Fields{"package": "remote_enforcer",
			"method":    "Supervise",
			"contextID": payload.ContextID,
			"error":     err.Error(),
		}).Info("Unable to initialize supervisor  ")

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
	payload := req.Payload.(rpcwrapper.UnEnforcePayload)
	return s.Enforcer.Unenforce(payload.ContextID)
}

//Unsupervise This method calls the unsupervise method on the supervisor created during initsupervisor
func (s *Server) Unsupervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Unsupervise Message Auth Failed")
		return errors.New(resp.Status)
	}
	payload := req.Payload.(rpcwrapper.UnSupervisePayload)
	return s.Supervisor.Unsupervise(payload.ContextID)
}

//Enforce this method calls the enforce method on the enforcer created during initenforcer
func (s *Server) Enforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Enforce Message Auth Failed")
		return errors.New(resp.Status)
	}
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
		log.WithFields(log.Fields{
			"package": "remote_enforcer",
		}).Info("Failed Runtime")
		return fmt.Errorf("Unable to instantiate puInfo")
	}

	if err := s.Enforcer.Enforce(payload.ContextID, puInfo); err != nil {
		resp.Status = err.Error()
		return err
	}

	log.WithFields(log.Fields{"package": "remote_enforcer",
		"method":    "Enforce",
		"contextID": payload.ContextID,
	}).Info("Enforcer enabled")

	resp.Status = ""

	return nil
}

// EnforcerExit this method is called when  we received a killrpocess message from the controller
// This allows a graceful exit of the enforcer
func (s *Server) EnforcerExit(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	//Cleanup resources held in this namespace
	s.Supervisor.Stop()
	s.Enforcer.Stop()
	s.statsclient.Stop()

	os.Exit(0)

	return nil
}

// LaunchRemoteEnforcer launches a remote enforcer
func LaunchRemoteEnforcer(service enforcer.PacketProcessor, logLevel log.Level) error {

	log.SetLevel(logLevel)
	log.SetFormatter(&log.TextFormatter{
		ForceColors:    true,
		DisableSorting: true,
	})

	namedPipe := os.Getenv(envSocketPath)

	secret := os.Getenv(envSecret)

	if len(secret) == 0 {
		os.Exit(-1)
	}

	rpchdl := rpcwrapper.NewRPCServer()

	server, err := NewServer(service, rpchdl, namedPipe, secret)
	if err != nil {
		return err
	}

	rpchdl.StartServer("unix", namedPipe, server)

	return nil
}
