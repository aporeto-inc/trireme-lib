package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	_ "github.com/aporeto-inc/trireme/enforcer/utils/nsenter"
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpc_payloads"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"
	"github.com/aporeto-inc/trireme/supervisor/provider"
)

const (
	ipcProtocol = "unix"
	defaultPath = "/var/run/default.sock"
)

//CollectorImpl exported
type CollectorImpl struct {
}

//CollectFlowEvent expoted
func (c *CollectorImpl) CollectFlowEvent(contextID string, tags policy.TagsMap, action string, mode string, sourceID string, tcpPacket *packet.Packet) {

}

//CollectContainerEvent exported
//This event should not be expected here in the enforcer process inside a particular container context
func (c *CollectorImpl) CollectContainerEvent(contextID string, ip string, tags policy.TagsMap, event string) {
}

//Server exported
type Server struct {
	MutualAuth bool
	Validity   time.Duration
	SecretType tokens.SecretsType
	ContextID  string
	CAPEM      []byte
	PublicPEM  []byte
	PrivatePEM []byte
	rpcchannel string
	rpchdl     *rpcWrapper.RPCWrapper
	Enforcer   enforcer.PolicyEnforcer
	Collector  collector.EventCollector
	Supervisor supervisor.Supervisor
}

//InitEnforcer exported
func (s *Server) InitEnforcer(req rpcWrapper.Request, resp *rpcWrapper.Response) error {

	collector := new(CollectorImpl)
	s.Collector = collector
	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	payload := req.Payload.(rpcWrapper.InitRequestPayload)
	usePKI := (payload.SecretType == tokens.PKIType)
	//Need to revisit what is packet processor
	if usePKI {
		//PKI params
		publicKeyAdder := tokens.NewPKISecrets(payload.PrivatePEM, payload.PublicPEM, payload.CAPEM, map[string]*ecdsa.PublicKey{})
		s.Enforcer = enforcer.NewDefaultDatapathEnforcer(payload.ContextID, collector, nil, publicKeyAdder)
	} else {
		//PSK params
		publicKeyAdder := tokens.NewPSKSecrets(payload.PublicPEM)
		s.Enforcer = enforcer.NewDefaultDatapathEnforcer(payload.ContextID, collector, nil, publicKeyAdder)
	}

	resp.Status = nil
	return nil
}

//InitSupervisor exported
func (s *Server) InitSupervisor(req rpcWrapper.Request, resp *rpcWrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	ipt, err := provider.NewGoIPTablesProvider()

	if err != nil {
		fmt.Printf("Failed to load Go-Iptables: %s", err)
		return err
		//panic("Failed to load Go-Iptables: ")
	}

	payload := req.Payload.(rpcWrapper.InitSupervisorPayload)

	s.Supervisor, err = supervisor.NewIPTablesSupervisor(s.Collector, s.Enforcer, ipt, payload.TargetNetworks, true)

	resp.Status = err
	return nil
}

//Supervise exported
func (s *Server) Supervise(req rpcWrapper.Request, resp *rpcWrapper.Response) error {
	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	payload := req.Payload.(rpcWrapper.SuperviseRequestPayload)
	pupolicy := payload.PuPolicy
	runtime := policy.NewPURuntime()
	puInfo := policy.PUInfoFromPolicyAndRuntime(payload.ContextID, pupolicy, runtime)
	puInfo.Runtime.SetPid(os.Getpid())
	s.Supervisor.Start()
	err := s.Supervisor.Supervise(payload.ContextID, puInfo)

	resp.Status = err
	return err
}

//Unenforce exported
func (s *Server) Unenforce(req rpcWrapper.Request, resp *rpcWrapper.Response) error {
	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	payload := req.Payload.(rpcWrapper.UnEnforcePayload)
	return s.Enforcer.Unenforce(payload.ContextID)

}

//Unsupervise exported
func (s *Server) Unsupervise(req rpcWrapper.Request, resp *rpcWrapper.Response) error {
	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	payload := req.Payload.(rpcWrapper.UnSupervisePayload)
	return s.Supervisor.Unsupervise(payload.ContextID)
}

//Enforce exported
func (s *Server) Enforce(req rpcWrapper.Request, resp *rpcWrapper.Response) error {
	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	payload := req.Payload.(rpcWrapper.EnforcePayload)
	pupolicy := payload.PuPolicy
	runtime := policy.NewPURuntime()
	puInfo := policy.PUInfoFromPolicyAndRuntime(payload.ContextID, pupolicy, runtime)
	if puInfo == nil {
		fmt.Println("Failed Runtime")
	}
	s.Enforcer.Start()
	err := s.Enforcer.Enforce(payload.ContextID, puInfo)
	resp.Status = err
	return err

}

//EnforcerExit exported
func (s *Server) EnforcerExit(req rpcWrapper.Request, resp *rpcWrapper.Response) error {
	os.Exit(0)
	return nil
}
func main() {
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{})
	namedPipe := os.Getenv("SOCKET_PATH")
	server := new(Server)
	rpchdl := rpcWrapper.NewRPCServer()
	//Map not initialized here since we don't use it on the server
	server.rpcchannel = namedPipe
	err := rpchdl.StartServer("unix", namedPipe, server)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	os.Exit(0)
}
