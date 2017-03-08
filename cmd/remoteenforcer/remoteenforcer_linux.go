// +build linux

package remoteenforcer

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"os/user"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer"
	_ "github.com/aporeto-inc/trireme/enforcer/utils/nsenter"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"
)

const (
	ipcProtocol         = "unix"
	defaultPath         = "/var/run/default.sock"
	defaultTimeInterval = 1
)

//Server : This is the structure for maintaining state required by the remote enforcer.
//It is cache of variables passed by th controller to the remote enforcer and other handles
//required by the remote enforcer to talk to the external processes
type Server struct {
	MutualAuth  bool
	Validity    time.Duration
	SecretType  tokens.SecretsType
	rpcSecret   string
	ContextID   string
	CAPEM       []byte
	PublicPEM   []byte
	PrivatePEM  []byte
	StatsClient *rpcwrapper.RPCWrapper
	Enforcer    enforcer.PolicyEnforcer
	Collector   collector.EventCollector
	Supervisor  supervisor.Supervisor
	Service     enforcer.PacketProcessor
	pupolicy    *policy.PUPolicy
	rpcchannel  string
	rpchdl      *rpcwrapper.RPCWrapper
	Excluder    supervisor.Excluder
}

// NewServer starts a new server
func NewServer(service enforcer.PacketProcessor, rpcchan string, secret string) *Server {
	return &Server{
		pupolicy:   nil,
		Service:    service,
		rpcchannel: rpcchan,
		rpcSecret:  secret,
	}
}

// InitEnforcer is a function called from the controller using RPC. It intializes data structure required by the
// remote enforcer
func (s *Server) InitEnforcer(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	//Check if sucessfully switched namespace
	nsEnterState := os.Getenv("NSENTER_ERROR_STATE")
	if len(nsEnterState) != 0 {
		resp.Status = (nsEnterState)
		return errors.New(resp.Status)
	}

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Message Auth Failed")
		return errors.New(resp.Status)
	}

	collectorInstance := &CollectorImpl{
		Flows: map[string]*collector.FlowRecord{},
	}

	s.Collector = collectorInstance

	payload := req.Payload.(rpcwrapper.InitRequestPayload)

	if payload.SecretType == tokens.PKIType {
		//PKI params
		secrets := tokens.NewPKISecrets(payload.PrivatePEM, payload.PublicPEM, payload.CAPEM, map[string]*ecdsa.PublicKey{})
		s.Enforcer = enforcer.NewDatapathEnforcer(
			payload.MutualAuth,
			payload.FqConfig,
			collectorInstance,
			s.Service,
			secrets,
			payload.ServerID,
			payload.Validity,
			constants.RemoteContainer)
	} else {
		//PSK params
		secrets := tokens.NewPSKSecrets(payload.PrivatePEM)
		s.Enforcer = enforcer.NewDatapathEnforcer(
			payload.MutualAuth,
			payload.FqConfig,
			collectorInstance,
			s.Service,
			secrets,
			payload.ServerID,
			payload.Validity,
			constants.RemoteContainer)
	}

	s.Enforcer.Start()

	statsClient := &StatsClient{collector: collectorInstance, server: s, Rpchdl: rpcwrapper.NewRPCWrapper()}

	s.connectStatsClient(statsClient)

	resp.Status = ""

	return nil
}

// InitSupervisor is a function called from the controller over RPC. It initializes data structure required by the supervisor
func (s *Server) InitSupervisor(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Message Auth Failed")
		return errors.New(resp.Status)
	}

	payload := req.Payload.(rpcwrapper.InitSupervisorPayload)
	switch payload.CaptureMethod {
	case rpcwrapper.IPSets:
		//TO DO
		return fmt.Errorf("IPSets not supported yet")
	default:

		supervisorHandle, err := supervisor.NewSupervisor(s.Collector,
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
		s.Excluder = supervisorHandle
		s.Supervisor = supervisorHandle

	}

	s.Supervisor.Start()

	resp.Status = ""
	return nil
}

//Supervise This method calls the supervisor method on the supervisor created during initsupervisor
func (s *Server) Supervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Message Auth Failed")
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
			"method": "Supervise",
			"error":  err.Error(),
		}).Info("Supervise status remote_enforcer ")
	}
	if err != nil {
		resp.Status = err.Error()
	}

	//We are good here now add the Excluded ip list as well
	return s.Excluder.AddExcludedIP(payload.ExcludedIP)

}

//Unenforce this method calls the unenforce method on the enforcer created from initenforcer
func (s *Server) Unenforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Message Auth Failed")
		return errors.New(resp.Status)
	}
	payload := req.Payload.(rpcwrapper.UnEnforcePayload)
	return s.Enforcer.Unenforce(payload.ContextID)
}

//Unsupervise This method calls the unsupervise method on the supervisor created during initsupervisor
func (s *Server) Unsupervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Message Auth Failed")
		return errors.New(resp.Status)
	}
	payload := req.Payload.(rpcwrapper.UnSupervisePayload)
	return s.Supervisor.Unsupervise(payload.ContextID)
}

//Enforce this method calls the enforce method on the enforcer created during initenforcer
func (s *Server) Enforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Message Auth Failed")
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
		nil)

	runtime := policy.NewPURuntimeWithDefaults()
	puInfo := policy.PUInfoFromPolicyAndRuntime(payload.ContextID, pupolicy, runtime)
	if puInfo == nil {
		log.WithFields(log.Fields{
			"package": "remote_enforcer",
		}).Info("Failed Runtime")
		return fmt.Errorf("Unable to instantiate puInfo")
	}
	err := s.Enforcer.Enforce(payload.ContextID, puInfo)
	log.WithFields(log.Fields{"package": "remote_enforcer",
		"method": "Enforce",
		"error":  err,
	}).Info("ENFORCE STATUS")
	if err != nil {
		resp.Status = err.Error()
	}
	return err
}

//EnforcerExit this method is called when  we received a killrpocess message from the controller
//THis allows a graceful exit of the enforcer
func (s *Server) EnforcerExit(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	//Cleanup resources held in this namespace
	s.Supervisor.Stop()
	s.Enforcer.Stop()
	os.Exit(0)
	return nil
}

func (s *Server) AddExcludedIP(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	if !s.rpchdl.CheckValidity(&req, s.rpcSecret) {
		resp.Status = ("Message Auth Failed")
		return errors.New(resp.Status)
	}
	payload := req.Payload.(rpcwrapper.ExcludeIPRequestPayload)
	return s.Excluder.AddExcludedIP(payload.Ip)

}

// LaunchRemoteEnforcer launches a remote enforcer
func LaunchRemoteEnforcer(service enforcer.PacketProcessor, logLevel log.Level) {

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

	server := NewServer(service, namedPipe, secret)

	rpchdl := rpcwrapper.NewRPCServer()

	userDetails, _ := user.Current()
	log.WithFields(log.Fields{"package": "remote_enforcer",
		"uid":      userDetails.Uid,
		"gid":      userDetails.Gid,
		"username": userDetails.Username,
	}).Info("Enforcer user id")

	rpchdl.StartServer("unix", namedPipe, server)

	server.EnforcerExit(rpcwrapper.Request{}, nil)

	os.Exit(0)
}
