package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	_ "github.com/aporeto-inc/trireme/enforcer/utils/nsenter"
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcWrapper"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"
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

	Enforcer   enforcer.PolicyEnforcer
	Collector  collector.EventCollector
	Supervisor supervisor.Supervisor
}

//InitEnforcer exported
func (s *Server) InitEnforcer(req rpcWrapper.Request, resp *rpcWrapper.Response) error {

	collector := new(CollectorImpl)
	s.Collector = collector
	if !rpcWrapper.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	payload := req.Payload.(rpcWrapper.InitRequestPayload)
	usePKI := (payload.SecretType == tokens.PKIType)

	if usePKI {
		//PKI params
		publicKeyAdder := tokens.NewPKISecrets(payload.PrivatePEM, payload.PublicPEM, payload.CAPEM, map[string]*ecdsa.PublicKey{})
		s.Enforcer = enforcer.NewDefaultDatapathEnforcer(payload.ContextID, collector, publicKeyAdder)
	} else {
		//PSK params
		publicKeyAdder := tokens.NewPSKSecrets(payload.PublicPEM)
		s.Enforcer = enforcer.NewDefaultDatapathEnforcer(payload.ContextID, collector, publicKeyAdder)
	}

	resp.Status = nil
	return nil
}

//InitSupervisor exported
func (s *Server) InitSupervisor(req rpcWrapper.Request, resp *rpcWrapper.Response) error {

	if !rpcWrapper.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	ipt, err := supervisor.NewGoIPTablesProvider()

	if err != nil {
		fmt.Printf("Failed to load Go-Iptables: %s", err)
		return err
		//panic("Failed to load Go-Iptables: ")
	}

	payload := req.Payload.(rpcWrapper.InitSupervisorPayload)

	s.Supervisor, err = supervisor.NewIPTablesSupervisor(s.Collector, s.Enforcer, ipt, payload.TargetNetworks)

	resp.Status = err
	return nil
}

//Supervise exported
func (s *Server) Supervise(req rpcWrapper.Request, resp *rpcWrapper.Response) error {
	if !rpcWrapper.CheckValidity(&req) {
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
	if !rpcWrapper.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	payload := req.Payload.(rpcWrapper.UnEnforcePayload)
	return s.Enforcer.Unenforce(payload.ContextID)

}

//Unsupervise exported
func (s *Server) Unsupervise(req rpcWrapper.Request, resp *rpcWrapper.Response) error {
	if !rpcWrapper.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	payload := req.Payload.(rpcWrapper.UnSupervisePayload)
	return s.Supervisor.Unsupervise(payload.ContextID)
}

//Enforce exported
func (s *Server) Enforce(req rpcWrapper.Request, resp *rpcWrapper.Response) error {
	if !rpcWrapper.CheckValidity(&req) {
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
func main() {
	namedPipe := os.Getenv("SOCKET_PATH")
	server := new(Server)
	err := rpcWrapper.StartServer("unix", namedPipe, server)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	os.Exit(0)
}
