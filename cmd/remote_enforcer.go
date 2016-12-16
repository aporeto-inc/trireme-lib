package main

import (
	"container/list"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	_ "github.com/aporeto-inc/trireme/enforcer/utils/nsenter"
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"
	"github.com/aporeto-inc/trireme/supervisor/iptablesutils"
	"github.com/aporeto-inc/trireme/supervisor/provider"
)

const (
	ipcProtocol         = "unix"
	defaultPath         = "/var/run/default.sock"
	statsContextID      = "UNUSED"
	defaulttimeInterval = 2
	envStatsChannelPath = "STATSCHANNEL_PATH"
	envSocketPath       = "SOCKET_PATH"
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
	defer c.Unlock()
	c.Flowentries.PushBack(&collectorentry{L4FlowHash: l4FlowHash, entry: payload})

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
	rpchdl      *rpcwrapper.RPCWrapper
	StatsClient *rpcwrapper.RPCWrapper
	Enforcer    enforcer.PolicyEnforcer
	Collector   collector.EventCollector
	Supervisor  supervisor.Supervisor
}

type StatsClient struct {
	collector *CollectorImpl
	server    *Server
	FlowCache *cache.Cache
	Rpchdl    *rpcwrapper.RPCWrapper
}

func (s *StatsClient) SendStats() {
	//We are connected and lets pack and ship
	rpcpayload := &rpcwrapper.StatsPayload{}
	var request rpcwrapper.Request
	var response rpcwrapper.Response
	var statsInterval time.Duration
	rpcpayload.NumFlows = 0
	EnvstatsInterval, err := strconv.Atoi(os.Getenv("STATS_INTERVAL"))

	if err == nil && EnvstatsInterval != 0 {
		statsInterval = time.Duration(EnvstatsInterval) * time.Second
	} else {
		statsInterval = defaulttimeInterval * time.Second
	}

	starttime := time.Now()
	for {
		s.collector.Lock()
		for !(s.collector.Flowentries.Len() > 0) {
			s.collector.Unlock()
			time.Sleep(statsInterval)
			s.collector.Lock()
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
		}
		if time.Since(starttime) > statsInterval {
			//Send out everything we have in the payload
			request.Payload = rpcpayload
			err = s.Rpchdl.RemoteCall(statsContextID, "StatsServer.GetStats", &request, &response)

			starttime = time.Now()
		}

	}
}
func (s *Server) connectStatsClient(statsClient *StatsClient) error {

	statschannel := os.Getenv(envStatsChannelPath)
	err := statsClient.Rpchdl.NewRPCClient(statsContextID, statschannel)
	if err != nil {
		log.WithFields(log.Fields{"package": "remote_enforcer",
			"error": err,
		}).Error("Stats RPC client cannot connect")
	}
	_, err = statsClient.Rpchdl.GetRPCClient(statsContextID)

	go statsClient.SendStats()
	return err
}

//InitEnforcer exported
func (s *Server) InitEnforcer(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	collector := &CollectorImpl{}
	collector.Flowentries = list.New()
	s.Collector = collector
	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	payload := req.Payload.(rpcwrapper.InitRequestPayload)
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
	statsClient := &StatsClient{collector: collector, server: s, FlowCache: cache.NewCacheWithExpiration(120*time.Second, 1000), Rpchdl: rpcwrapper.NewRPCWrapper()}
	s.connectStatsClient(statsClient)

	resp.Status = nil
	return nil
}

//InitSupervisor exported
func (s *Server) InitSupervisor(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	ipt, err := provider.NewGoIPTablesProvider()

	if err != nil {
		log.WithFields(log.Fields{"package": "remote_enforcer",
			"Error": err,
		}).Error("Failed to load Go-Iptables")
		return err
	}

	payload := req.Payload.(rpcwrapper.InitSupervisorPayload)
	ipu := iptablesutils.NewIptableUtils(ipt, true)
	s.Supervisor, err = supervisor.NewIPTablesSupervisor(s.Collector, s.Enforcer, ipu, payload.TargetNetworks, true)
	s.Supervisor.Start()
	resp.Status = err
	return nil
}

//Supervise exported
func (s *Server) Supervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	payload := req.Payload.(rpcwrapper.SuperviseRequestPayload)
	pupolicy := payload.PuPolicy
	runtime := policy.NewPURuntime()
	puInfo := policy.PUInfoFromPolicyAndRuntime(payload.ContextID, pupolicy, runtime)
	puInfo.Runtime.SetPid(os.Getpid())
	log.WithFields(log.Fields{"package": "remote_enforcer",
		"method": "Supervise",
	}).Info("Called Supervise Start in remote_enforcer")

	err := s.Supervisor.Supervise(payload.ContextID, puInfo)
	log.WithFields(log.Fields{"package": "remote_enforcer",
		"method": "Supervise",
		"error":  err,
	}).Info("Supervise status remote_enforcer ")
	resp.Status = err
	return err
}

//Unenforce exported
func (s *Server) Unenforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	payload := req.Payload.(rpcwrapper.UnEnforcePayload)
	return s.Enforcer.Unenforce(payload.ContextID)
}

//Unsupervise exported
func (s *Server) Unsupervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	payload := req.Payload.(rpcwrapper.UnSupervisePayload)
	return s.Supervisor.Unsupervise(payload.ContextID)
}

//Enforce exported
func (s *Server) Enforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return nil
	}
	payload := req.Payload.(rpcwrapper.EnforcePayload)
	pupolicy := payload.PuPolicy
	runtime := policy.NewPURuntime()
	puInfo := policy.PUInfoFromPolicyAndRuntime(payload.ContextID, pupolicy, runtime)
	if puInfo == nil {
		log.WithFields(log.Fields{"package": "remote_enforcer"}).Info("Failed Runtime")
	}
	log.WithFields(log.Fields{"package": "remote_enforcer",
		"method": "Enforce",
	}).Info("Called enforce in remote enforcer")

	err := s.Enforcer.Enforce(payload.ContextID, puInfo)
	log.WithFields(log.Fields{"package": "remote_enforcer",
		"method": "Enforce",
		"error":  err,
	}).Info("ENFORCE STATUS")
	resp.Status = err
	return err

}

//EnforcerExit exported
func (s *Server) EnforcerExit(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	os.Exit(0)
	return nil
}
func main() {
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{})
	namedPipe := os.Getenv(envSocketPath)
	server := &Server{}
	rpchdl := rpcwrapper.NewRPCServer()
	//Map not initialized here since we don't use it on the server
	server.rpcchannel = namedPipe
	flag.Parse()
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
