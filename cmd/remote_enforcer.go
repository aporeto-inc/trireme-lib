package main

import (
	"container/list"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"os/user"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/cache"
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
	ipcProtocol    = "unix"
	defaultPath    = "/var/run/default.sock"
	statsContextID = "UNUSED"
)

//CollectorImpl exported
type CollectorImpl struct {
	Flowentries *list.List
	sync.RWMutex
}
type collectorentry struct {
	L4FlowHash string
	entry      *enforcer.StatsPayload
}

//CollectFlowEvent expoted
func (c *CollectorImpl) CollectFlowEvent(contextID string, tags policy.TagsMap, action string, mode string, sourceID string, tcpPacket *packet.Packet) {
	l4FlowHash := tcpPacket.L4FlowHash()
	payload := &enforcer.StatsPayload{ContextID: contextID,
		Tags:   tags,
		Action: action,
		Mode:   mode,
		Source: sourceID,
		Packet: tcpPacket,
	}

	c.Lock()
	c.Flowentries.PushBack(&collectorentry{L4FlowHash: l4FlowHash, entry: payload})
	c.Unlock()
}

//CollectContainerEvent exported
//This event should not be expected here in the enforcer process inside a particular container context
func (c *CollectorImpl) CollectContainerEvent(contextID string, ip string, tags policy.TagsMap, event string) {
}

//Server exported
type Server struct {
	MutualAuth  bool
	Validity    time.Duration
	SecretType  tokens.SecretsType
	ContextID   string
	CAPEM       []byte
	PublicPEM   []byte
	PrivatePEM  []byte
	rpcchannel  string
	rpchdl      *rpcWrapper.RPCWrapper
	StatsClient *rpcWrapper.RPCWrapper
	Enforcer    enforcer.PolicyEnforcer
	Collector   collector.EventCollector
	Supervisor  supervisor.Supervisor
}

type StatsClient struct {
	collector *CollectorImpl
	s         *Server
	FlowCache *cache.Cache
	Rpchdl    *rpcWrapper.RPCWrapper
}

func (s *StatsClient) SendStats() {
	//We are connected and lets pack and ship
	rpcpayload := new(rpcWrapper.StatsPayload)
	var request rpcWrapper.Request
	var response rpcWrapper.Response
	rpcpayload.NumFlows = 0
	starttime := time.Now()
	for {

		s.collector.Lock()
		if !(s.collector.Flowentries.Len() > 0) {
			s.collector.Unlock()
			//starttime = time.Now()
			continue
		}
		s.collector.Unlock()
		element := s.collector.Flowentries.Remove(s.collector.Flowentries.Front())
		//Now we can proceed lock free flowcache is not shared
		_, err := s.FlowCache.Get(element.(*collectorentry).L4FlowHash)
		if err != nil {
			//this is new flow add it to our rpc payload
			rpcpayload.NumFlows = rpcpayload.NumFlows + 1
			rpcpayload.Flows = append(rpcpayload.Flows, *element.(*collectorentry).entry)

		} else {
			//Do nothing since we have added this flow already
		}
		if time.Since(starttime) > 2*time.Second {
			//Send out everything we have in the payload
			request.Payload = rpcpayload
			err = s.Rpchdl.RemoteCall(statsContextID, "RPCSERVER.GetStats", &request, &response)

			starttime = time.Now()
		}

	}
}
func (s *Server) connectStatsClient(statsClient *StatsClient) error {

	statschannel := os.Getenv("STATSCHANNEL_PATH")
	err := statsClient.Rpchdl.NewRPCClient(statsContextID, statschannel)
	if err != nil {
		log.WithFields(log.Fields{"package": "remote_enforcer", "error": err}).Error("Stats RPC client cannot connect")
	}
	_, err = statsClient.Rpchdl.GetRPCClient(statsContextID)

	go statsClient.SendStats()
	return err
}

//InitEnforcer exported
func (s *Server) InitEnforcer(req rpcWrapper.Request, resp *rpcWrapper.Response) error {
	collector := new(CollectorImpl)
	collector.Flowentries = list.New()
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
	s.Enforcer.Start()
	statsClient := &StatsClient{collector: collector, s: s, FlowCache: cache.NewCacheWithExpiration(120*time.Second, 1000), Rpchdl: rpcWrapper.NewRPCWrapper()}
	s.connectStatsClient(statsClient)

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
	s.Supervisor.Start()
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
	log.WithFields(log.Fields{"package": "remote_enforcer", "method": "Supervise"}).Info("Called Supervise Start in remote_enforcer")

	err := s.Supervisor.Supervise(payload.ContextID, puInfo)
	log.WithFields(log.Fields{"package": "remote_enforcer", "method": "Supervise", "error": err}).Info("Supervise status remote_enforcer ")
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
	log.WithFields(log.Fields{"package": "remote_enforcer", "method": "Enforce"}).Info("Called enforce in remote enforcer")

	err := s.Enforcer.Enforce(payload.ContextID, puInfo)
	log.WithFields(log.Fields{"package": "remote_enforcer", "method": "Enforce", "error": err}).Info("ENFORCE STATUS")
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

	userDetails, _ := user.Current()
	log.WithFields(log.Fields{"package": "remote_enforcer",
		"uid":      userDetails.Uid,
		"gid":      userDetails.Gid,
		"username": userDetails.Username,
	}).Info("Enforcer user id")
	err := rpchdl.StartServer("unix", namedPipe, server)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	os.Exit(0)
}
