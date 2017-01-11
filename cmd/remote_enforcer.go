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
)

const (
	ipcProtocol         = "unix"
	defaultPath         = "/var/run/default.sock"
	statsContextID      = "UNUSED"
	defaultTimeInterval = 1
	envStatsChannelPath = "STATSCHANNEL_PATH"
	envSocketPath       = "SOCKET_PATH"
)

//CollectorImpl : This is a local implementation for the collector interface
// It has a flow entries cache which contains unique flows that are reported back to the
//controller/launcher process
type CollectorImpl struct {
	cond        *sync.Cond
	FlowEntries *list.List
}
type collectorentry struct {
	L4FlowHash string
	entry      *enforcer.StatsPayload
}

//CollectFlowEvent expoted
func (c *CollectorImpl) CollectFlowEvent(contextID string, tags *policy.TagsMap, action string, mode string, sourceID string, tcpPacket *packet.Packet) {

	l4FlowHash := tcpPacket.L4FlowHash()
	payload := &enforcer.StatsPayload{ContextID: contextID,
		Tags:   tags,
		Action: action,
		Mode:   mode,
		Source: sourceID,
		Packet: tcpPacket,
	}

	c.cond.L.Lock()
	c.FlowEntries.PushBack(&collectorentry{L4FlowHash: l4FlowHash, entry: payload})
	c.cond.L.Unlock()
	if c.FlowEntries.Len() == 1 {
		c.cond.Signal()
	}

}

//CollectContainerEvent exported
//This event should not be expected here in the enforcer process inside a particular container context
func (c *CollectorImpl) CollectContainerEvent(contextID string, ip string, tags *policy.TagsMap, event string) {
	log.WithFields(log.Fields{"package": "remoteEnforcer",
		"Msg": "Unexpected call to CollectContainer Event",
	}).Error("Received a container event in Remote Enforcer ")
}

//Server : This is the structure for maintaining state required by the remote enforcer.
//It is cache of variables passed by th controller to the remote enforcer and other handles
//required by the remote enforcer to talk to the external processes
type Server struct {
	MutualAuth  bool
	Validity    time.Duration
	SecretType  tokens.SecretsType
	ContextID   string
	CAPEM       []byte
	PublicPEM   []byte
	PrivatePEM  []byte
	pupolicy    *policy.PUPolicy
	rpcchannel  string
	rpchdl      *rpcwrapper.RPCWrapper
	StatsClient *rpcwrapper.RPCWrapper
	Enforcer    enforcer.PolicyEnforcer
	Collector   collector.EventCollector
	Supervisor  supervisor.Supervisor
}

//StatsClient  This is the struct for storing state for the rpc client
//which reports flow stats back to the controller process
type StatsClient struct {
	collector *CollectorImpl
	server    *Server
	FlowCache *cache.Cache
	Rpchdl    *rpcwrapper.RPCWrapper
}

//SendStats  async function which makes a rpc call to send stats every STATS_INTERVAL
func (s *StatsClient) SendStats() {

	//We are connected and lets pack and ship
	rpcPayload := &rpcwrapper.StatsPayload{}
	var request rpcwrapper.Request
	var response rpcwrapper.Response
	var statsInterval time.Duration
	rpcPayload.NumFlows = 0
	EnvstatsInterval, err := strconv.Atoi(os.Getenv("STATS_INTERVAL"))

	if err == nil && EnvstatsInterval != 0 {
		statsInterval = time.Duration(EnvstatsInterval) * time.Second
	} else {
		statsInterval = defaultTimeInterval * time.Second
	}

	starttime := time.Now()
	for {
		s.collector.cond.L.Lock()
		if !(s.collector.FlowEntries.Len() > 0) {
			s.collector.cond.Wait()
		}
		element := s.collector.FlowEntries.Remove(s.collector.FlowEntries.Front())
		s.collector.cond.L.Unlock()

		//Now we can proceed lock free flowcache is not shared
		_, err := s.FlowCache.Get(element.(*collectorentry).L4FlowHash)
		if err != nil {
			//this is new flow add it to our rpc payload
			rpcPayload.NumFlows = rpcPayload.NumFlows + 1
			rpcPayload.Flows = append(rpcPayload.Flows, *element.(*collectorentry).entry)
		}
		if time.Since(starttime) > statsInterval {
			//Send out everything we have in the payload
			request.Payload = rpcPayload
			err = s.Rpchdl.RemoteCall(statsContextID,
				"StatsServer.GetStats",
				&request,
				&response,
			)
			starttime = time.Now()
		}

	}
}

//connectStatsCLient  This is an private function called by the remoteenforcer to connect back
//to the controller over a stats channel
func (s *Server) connectStatsClient(statsClient *StatsClient) error {

	statsChannel := os.Getenv(envStatsChannelPath)
	err := statsClient.Rpchdl.NewRPCClient(statsContextID, statsChannel)
	if err != nil {
		log.WithFields(log.Fields{"package": "remote_enforcer",
			"error": err.Error(),
		}).Error("Stats RPC client cannot connect")
	}
	_, err = statsClient.Rpchdl.GetRPCClient(statsContextID)

	go statsClient.SendStats()
	return err
}

// InitEnforcer is a function called from the controller using RPC. It intializes data structure required by the
// remote enforcer
func (s *Server) InitEnforcer(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return resp.Status
	}

	collectorInstance := &CollectorImpl{
		cond: &sync.Cond{
			L: &sync.Mutex{},
		},
		FlowEntries: list.New(),
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
			nil, // TODO - PASS SERVICE ARGUMENTS
			secrets,
			payload.ServerID,
			payload.Validity,
			true)
	} else {
		//PSK params
		secrets := tokens.NewPSKSecrets(payload.PrivatePEM)
		s.Enforcer = enforcer.NewDatapathEnforcer(
			payload.MutualAuth,
			payload.FqConfig,
			collectorInstance,
			nil, // TODO - PASS SERVICE ARGUMENTS
			secrets,
			payload.ServerID,
			payload.Validity,
			true)
	}

	s.Enforcer.Start()

	statsClient := &StatsClient{collector: collectorInstance, server: s, FlowCache: cache.NewCacheWithExpiration(120 * time.Second), Rpchdl: rpcwrapper.NewRPCWrapper()}

	s.connectStatsClient(statsClient)

	resp.Status = nil

	return resp.Status
}

// InitSupervisor is a function called from the controller over RPC. It initializes data structure required by the supervisor
func (s *Server) InitSupervisor(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return resp.Status
	}

	payload := req.Payload.(rpcwrapper.InitSupervisorPayload)
	switch payload.CaptureMethod {
	case rpcwrapper.IPSets:
		//TO DO
		return fmt.Errorf("IPSets not supported yet")
	default:
		var err error
		s.Supervisor, err = supervisor.NewSupervisor(s.Collector,
			s.Enforcer,
			payload.TargetNetworks,
			supervisor.RemoteContainer,
			supervisor.IPTables,
		)
		if err != nil {
			log.WithFields(log.Fields{
				"package": "remote_enforcer",
				"Error":   err.Error(),
			}).Error("Failed to instantiate the iptables supervisor")
			resp.Status = err
			return resp.Status
		}

	}

	s.Supervisor.Start()

	resp.Status = nil
	return resp.Status
}

//Supervise This method calls the supervisor method on the supervisor created during initsupervisor
func (s *Server) Supervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return resp.Status
	}

	payload := req.Payload.(rpcwrapper.SuperviseRequestPayload)
	pupolicy := policy.NewPUPolicy(payload.ManagementID,
		payload.TriremeAction,
		payload.IngressACLs,
		payload.EgressACLs,
		payload.TransmitterRules,
		payload.ReceiverRules,
		payload.Identity,
		payload.Annotations,
		payload.PolicyIPs,
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
	resp.Status = err
	return resp.Status
}

//Unenforce this method calls the unenforce method on the enforcer created from initenforcer
func (s *Server) Unenforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return resp.Status
	}
	payload := req.Payload.(rpcwrapper.UnEnforcePayload)
	return s.Enforcer.Unenforce(payload.ContextID)
}

//Unsupervise This method calls the unsupervise method on the supervisor created during initsupervisor
func (s *Server) Unsupervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return resp.Status
	}
	payload := req.Payload.(rpcwrapper.UnSupervisePayload)
	return s.Supervisor.Unsupervise(payload.ContextID)
}

//Enforce this method calls the enforce method on the enforcer created during initenforcer
func (s *Server) Enforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpchdl.CheckValidity(&req) {
		resp.Status = errors.New("Message Auth Failed")
		return resp.Status
	}
	payload := req.Payload.(rpcwrapper.EnforcePayload)

	pupolicy := policy.NewPUPolicy(payload.ManagementID,
		payload.TriremeAction,
		payload.IngressACLs,
		payload.EgressACLs,
		payload.TransmitterRules,
		payload.ReceiverRules,
		payload.Identity,
		payload.Annotations,
		payload.PolicyIPs,
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
	resp.Status = err
	return err
}

//EnforcerExit this method is called when  we received a killrpocess message from the controller
//THis allows a graceful exit of the enforcer
func (s *Server) EnforcerExit(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	os.Exit(0)
	return nil
}
func main() {

	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{})
	namedPipe := os.Getenv(envSocketPath)
	server := &Server{pupolicy: nil}
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
