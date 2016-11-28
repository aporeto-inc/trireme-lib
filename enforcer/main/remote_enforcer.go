package main

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"os/signal"
	"time"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"
	_ "github.com/aporeto-inc/trireme/utils/nsenter"
	"github.com/aporeto-inc/trireme/utils/packet"
	"github.com/aporeto-inc/trireme/utils/rpc_payloads"
	"github.com/aporeto-inc/trireme/utils/tokens"
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
func (s *Server) InitEnforcer(req rpcWrapper.InitRequestPayload, resp *rpcWrapper.InitResponsePayload) error {

	collector := new(CollectorImpl)
	s.Collector = collector
	payload := req
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

	resp.Status = rpcWrapper.SUCCESS
	return nil
}

//InitSupervisor exported
func (s *Server) InitSupervisor(req rpcWrapper.InitSupervisorPayload, resp *rpcWrapper.InitResponsePayload) error {

	ipt, err := supervisor.NewGoIPTablesProvider()
	payload := req
	if err != nil {
		fmt.Printf("Failed to load Go-Iptables: %s", err)
		return err
		//panic("Failed to load Go-Iptables: ")
	}
	s.Supervisor, _ = supervisor.NewIPTablesSupervisor(s.Collector, s.Enforcer, ipt, payload.TargetNetworks)

	resp.Status = rpcWrapper.SUCCESS
	return nil
}

//Supervise exported
func (s *Server) Supervise(req rpcWrapper.SuperviseRequestPayload, resp *rpcWrapper.SuperviseResponsePayload) error {
	payload := req
	pupolicy := payload.PuPolicy
	runtime := policy.NewPURuntime()
	puInfo := policy.PUInfoFromPolicyAndRuntime(payload.ContextID, pupolicy, runtime)
	puInfo.Runtime.SetPid(os.Getpid())
	s.Supervisor.Start()
	err := s.Supervisor.Supervise(payload.ContextID, puInfo)

	resp.Status = rpcWrapper.SUCCESS
	return err
}

//Unenforce exported
func (s *Server) Unenforce(req rpcWrapper.UnEnforcePayload, resp *rpcWrapper.UnEnforceResponsePayload) error {
	return s.Enforcer.Unenforce(req.ContextID)

}

//Unsupervise exported
func (s *Server) Unsupervise(req rpcWrapper.UnEnforcePayload, resp *rpcWrapper.UnEnforceResponsePayload) error {
	return s.Supervisor.Unsupervise(req.ContextID)
}

//Enforce exported
func (s *Server) Enforce(req rpcWrapper.EnforcePayload, resp *rpcWrapper.EnforceResponsePayload) error {
	payload := req
	pupolicy := payload.PuPolicy
	runtime := policy.NewPURuntime()
	puInfo := policy.PUInfoFromPolicyAndRuntime(payload.ContextID, pupolicy, runtime)
	if puInfo == nil {
		fmt.Println("Failed Runtime")
	}
	s.Enforcer.Start()
	err := s.Enforcer.Enforce(payload.ContextID, puInfo)
	if err != nil {
		resp.Status = -1
	}
	resp.Status = rpcWrapper.SUCCESS
	return nil

}
func main() {
	namedPipe := os.Getenv("SOCKET_PATH")

	server := new(Server)
	rpc.Register(server)
	rpc.HandleHTTP()
	if len(namedPipe) == 0 {
		panic("Sock param not passed in environment")
	}
	listen, err := net.Listen(ipcProtocol, namedPipe)

	if err != nil {
		panic(err)
	}
	go http.Serve(listen, nil)
	defer func() {
		listen.Close()
	}()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	_, err = os.Stat(namedPipe)
	if !os.IsNotExist(err) {
		os.Remove(namedPipe)
	}
	os.Exit(0)
}
