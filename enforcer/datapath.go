package enforcer

// Go libraries
import (
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/lookup"
	"github.com/aporeto-inc/trireme/enforcer/netfilter"

	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/policy"
)

// datapathEnforcer is the structure holding all information about a connection filter
type datapathEnforcer struct {

	// Configuration parameters
	mutualAuthorization bool
	filterQueue         *FilterQueue
	tokenEngine         tokens.TokenEngine
	collector           collector.EventCollector
	service             PacketProcessor

	// Internal structures and caches
	// Key=ContextId Value=ContainerIP
	contextTracker cache.DataStore
	puTracker      cache.DataStore
	// Key=FlowHash Value=Connection. Created on syn packet from network with regular flow hash
	networkConnectionTracker cache.DataStore
	// Key=FlowHash Value=Connection. Created on syn packet from application with regular flow hash
	appConnectionTracker cache.DataStore
	// Key=Context Value=Connection. Create on syn packet from application with local context-id
	contextConnectionTracker cache.DataStore

	sourcePortCache      cache.DataStore
	destinationPortCache cache.DataStore

	// stats
	net    *InterfaceStats
	app    *InterfaceStats
	netTCP *PacketStats
	appTCP *PacketStats

	// ack size
	ackSize uint32

	// mode captures the mode of the enforcer
	mode constants.ModeType
	//handle to secrets we will retire tokenEngine
	secrets tokens.Secrets
}

// NewDatapathEnforcer will create a new data path structure. It instantiates the data stores
// needed to track sessions. The data path is started with a different call.
// Only required parameters must be provided. Rest a pre-populated with defaults.
func NewDatapathEnforcer(
	mutualAuth bool,
	filterQueue *FilterQueue,
	collector collector.EventCollector,
	service PacketProcessor,
	secrets tokens.Secrets,
	serverID string,
	validity time.Duration,
	mode constants.ModeType,
) PolicyEnforcer {

	tokenEngine, err := tokens.NewJWT(validity, serverID, secrets)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Fatal("Unable to create TokenEngine in enforcer")
	}

	d := &datapathEnforcer{
		contextTracker:           cache.NewCache(),
		puTracker:                cache.NewCache(),
		networkConnectionTracker: cache.NewCacheWithExpiration(time.Second * 60),
		appConnectionTracker:     cache.NewCacheWithExpiration(time.Second * 60),
		contextConnectionTracker: cache.NewCacheWithExpiration(time.Second * 60),
		sourcePortCache:          cache.NewCacheWithExpiration(time.Second * 60),
		destinationPortCache:     cache.NewCacheWithExpiration(time.Second * 60),
		filterQueue:              filterQueue,
		mutualAuthorization:      mutualAuth,
		service:                  service,
		collector:                collector,
		tokenEngine:              tokenEngine,
		net:                      &InterfaceStats{},
		app:                      &InterfaceStats{},
		netTCP:                   &PacketStats{},
		appTCP:                   &PacketStats{},
		ackSize:                  secrets.AckSize(),
		mode:                     mode,
		secrets:                  secrets,
	}

	if d.tokenEngine == nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Fatal("Unable to create enforcer")
	}
	return d
}

// NewDefaultDatapathEnforcer create a new data path with most things used by default
func NewDefaultDatapathEnforcer(
	serverID string,
	collector collector.EventCollector,
	service PacketProcessor,
	secrets tokens.Secrets,
	mode constants.ModeType,
) PolicyEnforcer {

	if collector == nil {
		log.WithFields(log.Fields{
			"package":  "enforcer",
			"serverID": serverID,
		}).Fatal("Collector must be given to NewDefaultDatapathEnforcer")
	}

	mutualAuthorization := false
	fqConfig := &FilterQueue{
		NetworkQueue:              DefaultNetworkQueue,
		NetworkQueueSize:          DefaultQueueSize,
		NumberOfNetworkQueues:     DefaultNumberOfQueues,
		ApplicationQueue:          DefaultApplicationQueue,
		ApplicationQueueSize:      DefaultQueueSize,
		NumberOfApplicationQueues: DefaultNumberOfQueues,
		MarkValue:                 DefaultMarkValue,
	}

	validity := time.Hour * 8760

	return NewDatapathEnforcer(
		mutualAuthorization,
		fqConfig,
		collector,
		service,
		secrets,
		serverID,
		validity,
		mode,
	)
}

func (d *datapathEnforcer) Enforce(contextID string, puInfo *policy.PUInfo) error {

	hashSlice, err := d.contextTracker.Get(contextID)

	if err != nil {
		return d.doCreatePU(contextID, puInfo)
	}

	if len(hashSlice.([]*DualHash)) == 0 {
		return fmt.Errorf("Unable to resolve context from existing hash")
	}

	puContext, err := d.puTracker.Get(hashSlice.([]*DualHash)[0].app)
	if err != nil {
		return d.doUpdatePU(puContext.(*PUContext), puInfo)
	}

	return d.doCreatePU(contextID, puInfo)

}

func (d *datapathEnforcer) createHashForProcess(puInfo *policy.PUInfo) []*DualHash {
	var hashSlice []*DualHash

	expectedMark, ok := puInfo.Runtime.Options().Get(cgnetcls.CgroupMarkTag)
	if !ok {
		expectedMark = ""
	}

	expectedPort, ok := puInfo.Runtime.Options().Get(cgnetcls.PortTag)
	if !ok {
		expectedPort = "0"
		hashSlice = append(hashSlice, &DualHash{
			app: "mark:" + expectedMark + "$",
			net: "port:" + expectedPort,
		})
		return hashSlice
	}

	portlist := strings.Split(expectedPort, ",")
	for _, port := range portlist {
		hashSlice = append(hashSlice, &DualHash{
			app: "mark:" + expectedMark + "$",
			net: "port:" + port,
		})
	}
	return hashSlice
}

func (d *datapathEnforcer) puHash(ip string, puInfo *policy.PUInfo) (hash []*DualHash) {

	if puInfo.Runtime.PUType() == constants.LinuxProcessPU {
		return d.createHashForProcess(puInfo)
	}

	return []*DualHash{&DualHash{
		app: ip,
		net: ip,
	}}
}

func (d *datapathEnforcer) doCreatePU(contextID string, puInfo *policy.PUInfo) error {

	ip := DefaultNetwork

	// This is to check that we are not doing this for a process in the host
	// processes managed by systemd will not have a separate IP
	// IP are not required to process rules we have for cgroup

	if d.mode == constants.LocalContainer && (puInfo.Runtime.PUType() == constants.ContainerPU) {
		if _, ok := puInfo.Policy.DefaultIPAddress(); !ok {
			log.WithFields(log.Fields{
				"package": "Enforcer",
			}).Info("Default IP address not found")
			return fmt.Errorf("No IP address found")
		}
		ip, _ = puInfo.Policy.DefaultIPAddress()
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid up address %s ", ip)
		}
	}
	pu := &PUContext{
		ID: contextID,
	}

	hashSlice := d.puHash(ip, puInfo)

	d.doUpdatePU(pu, puInfo)

	d.contextTracker.AddOrUpdate(contextID, hashSlice)

	for _, hash := range hashSlice {
		d.puTracker.AddOrUpdate(hash.app, pu)
		d.puTracker.AddOrUpdate(hash.net, pu)
	}

	return nil
}

func (d *datapathEnforcer) doUpdatePU(puContext *PUContext, containerInfo *policy.PUInfo) error {
	puContext.acceptRcvRules, puContext.rejectRcvRules = createRuleDB(containerInfo.Policy.ReceiverRules())
	puContext.acceptTxtRules, puContext.rejectTxtRules = createRuleDB(containerInfo.Policy.TransmitterRules())
	puContext.Identity = containerInfo.Policy.Identity()
	puContext.Annotations = containerInfo.Policy.Annotations()
	return nil
}

func (d *datapathEnforcer) Unenforce(contextID string) error {
	log.WithFields(log.Fields{
		"package":   "enforcer",
		"contextID": contextID,
	}).Debug("Unenforce IP")

	hashSlice, err := d.contextTracker.Get(contextID)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "enforcer",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Hash of IP  not found in Enforcer when unenforce")
		return fmt.Errorf("ContextID not found in Enforcer")
	}
	for _, hash := range hashSlice.([]*DualHash) {
		d.puTracker.Remove(hash.app)
		d.puTracker.Remove(hash.net)
	}
	d.contextTracker.Remove(contextID)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "enforcer",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("IP not found in Enforcer when unenforce")
		return fmt.Errorf("IP not found in Enforcer")
	}

	return nil
}

func (d *datapathEnforcer) GetFilterQueue() *FilterQueue {

	return d.filterQueue
}

// StartNetworkInterceptor will the process that processes  packets from the network
// Still has one more copy than needed. Can be improved.
func (d *datapathEnforcer) StartNetworkInterceptor() {
	var err error

	nfq := make([]*netfilter.NFQueue, d.filterQueue.NumberOfNetworkQueues)

	for i := uint16(0); i < d.filterQueue.NumberOfNetworkQueues; i++ {

		// Initalize all the queues
		nfq[i], err = netfilter.NewNFQueue(d.filterQueue.NetworkQueue+i, d.filterQueue.NetworkQueueSize, netfilter.NfDefaultPacketSize)

		if err != nil {
			log.WithFields(log.Fields{
				"package": "enforcer",
				"error":   err.Error(),
			}).Fatal("Unable to initialize netfilter queue - Aborting")
		}

		go func(i uint16) {
			for true {
				select {
				case packet := <-nfq[i].Packets:
					d.processNetworkPacketsFromNFQ(packet)
				}
			}
		}(i)

	}
}

// Start starts the application and network interceptors
func (d *datapathEnforcer) Start() error {

	log.WithFields(log.Fields{
		"package": "enforcer",
		"mode":    d.mode,
	}).Debug("Start enforcer")

	d.StartApplicationInterceptor()
	d.StartNetworkInterceptor()

	return nil
}

// Stop stops the enforcer
func (d *datapathEnforcer) Stop() error {
	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("Stop enforcer")
	return nil
}

// StartApplicationInterceptor will create a interceptor that processes
// packets originated from a local application
func (d *datapathEnforcer) StartApplicationInterceptor() {
	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("Start application interceptor")

	var err error

	nfq := make([]*netfilter.NFQueue, d.filterQueue.NumberOfApplicationQueues)

	for i := uint16(0); i < d.filterQueue.NumberOfApplicationQueues; i++ {
		nfq[i], err = netfilter.NewNFQueue(d.filterQueue.ApplicationQueue+i, d.filterQueue.ApplicationQueueSize, netfilter.NfDefaultPacketSize)

		if err != nil {
			log.WithFields(log.Fields{
				"package": "enforcer",
				"error":   err.Error(),
			}).Fatal("Unable to initialize netfilter queue - Aborting")
		}

		go func(i uint16) {
			for true {
				select {
				case packet := <-nfq[i].Packets:
					d.processApplicationPacketsFromNFQ(packet)
				}
			}
		}(i)
	}
}

func createRuleDB(policyRules *policy.TagSelectorList) (*lookup.PolicyDB, *lookup.PolicyDB) {

	acceptRules := lookup.NewPolicyDB()
	rejectRules := lookup.NewPolicyDB()

	for _, rule := range policyRules.TagSelectors {

		if rule.Action&policy.Accept != 0 {
			acceptRules.AddPolicy(rule)
		} else if rule.Action&policy.Reject != 0 {
			rejectRules.AddPolicy(rule)
		} else {
			continue
		}

	}

	return acceptRules, rejectRules
}

// processNetworkPacketsFromNFQ processes packets arriving from the network in an NF queue
func (d *datapathEnforcer) processNetworkPacketsFromNFQ(p *netfilter.NFPacket) {

	d.net.IncomingPackets++

	// Parse the packet - drop if parsing fails
	netPacket, err := packet.New(packet.PacketTypeNetwork, p.Buffer, p.Mark)

	if err != nil {
		d.net.CreateDropPackets++
		netPacket.Print(packet.PacketFailureCreate)
	} else if netPacket.IPProto == packet.IPProtocolTCP {
		err = d.processNetworkTCPPackets(netPacket)
	} else {
		d.net.ProtocolDropPackets++
		err = fmt.Errorf("Invalid IP Protocol %d", netPacket.IPProto)
	}

	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Debug("Error when processing network packets from NFQ")

		netfilter.SetVerdict(&netfilter.Verdict{
			V:           netfilter.NfDrop,
			Buffer:      netPacket.Buffer,
			Payload:     nil,
			Options:     nil,
			Xbuffer:     p.Xbuffer,
			ID:          p.ID,
			QueueHandle: p.QueueHandle,
		}, d.filterQueue.MarkValue)
		return
	}

	// Accept the packet
	netfilter.SetVerdict(&netfilter.Verdict{
		V:           netfilter.NfAccept,
		Buffer:      netPacket.Buffer,
		Payload:     netPacket.GetTCPData(),
		Options:     netPacket.GetTCPOptions(),
		Xbuffer:     p.Xbuffer,
		ID:          p.ID,
		QueueHandle: p.QueueHandle,
	}, d.filterQueue.MarkValue)
}

// processApplicationPackets processes packets arriving from an application and are destined to the network
func (d *datapathEnforcer) processApplicationPacketsFromNFQ(p *netfilter.NFPacket) {

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("process application packets from NFQ")

	d.app.IncomingPackets++
	// Being liberal on what we transmit - malformed TCP packets are let go
	// We are strict on what we accept on the other side, but we don't block
	// lots of things at the ingress to the network
	appPacket, err := packet.New(packet.PacketTypeApplication, p.Buffer, p.Mark)

	if err != nil {
		d.app.CreateDropPackets++
		appPacket.Print(packet.PacketFailureCreate)
	} else if appPacket.IPProto == packet.IPProtocolTCP {
		err = d.processApplicationTCPPackets(appPacket)
	} else {
		d.app.ProtocolDropPackets++
		err = fmt.Errorf("Invalid IP Protocol %d", appPacket.IPProto)
	}

	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Debug("Error when processing application packets from NFQ")

		netfilter.SetVerdict(&netfilter.Verdict{
			V:           netfilter.NfDrop,
			Buffer:      appPacket.Buffer,
			Payload:     nil,
			Options:     nil,
			Xbuffer:     p.Xbuffer,
			ID:          p.ID,
			QueueHandle: p.QueueHandle,
		}, d.filterQueue.MarkValue)
		return
	}

	// Accept the packet
	netfilter.SetVerdict(&netfilter.Verdict{
		V:           netfilter.NfAccept,
		Buffer:      appPacket.Buffer,
		Payload:     appPacket.GetTCPData(),
		Options:     appPacket.GetTCPOptions(),
		Xbuffer:     p.Xbuffer,
		ID:          p.ID,
		QueueHandle: p.QueueHandle,
	}, d.filterQueue.MarkValue)

}

func (d *datapathEnforcer) createPacketToken(ackToken bool, context *PUContext, auth *AuthInfo) []byte {
	claims := &tokens.ConnectionClaims{
		LCL: auth.LocalContext,
		RMT: auth.RemoteContext,
	}

	if !ackToken {
		claims.T = context.Identity
	}

	return d.secrets.CreateAndSign(tokens.JWTTokens, ackToken, claims)
}

func (d *datapathEnforcer) parsePacketToken(auth *AuthInfo, data []byte) (*tokens.ConnectionClaims, error) {

	// Validate the certificate and parse the token
	var claims *tokens.ConnectionClaims
	decodedinfo, cert := d.secrets.Decode(tokens.JWTTokens, false, data, auth.RemotePublicKey)
	claims = decodedinfo.(*tokens.ConnectionClaims)
	if claims == nil {
		return nil, fmt.Errorf("Cannot decode the token")
	}

	// We always a need a valid remote context ID
	remoteContextID, ok := claims.T.Get(TransmitterLabel)
	if !ok {
		return nil, fmt.Errorf("No Transmitter Label ")
	}

	auth.RemotePublicKey = cert
	auth.RemoteContext = claims.LCL
	auth.RemoteContextID = remoteContextID

	return claims, nil
}

// contextFromIP returns the context from the default IP if remote. otherwise
// it returns the context from the passed IP
func (d *datapathEnforcer) contextFromIP(app bool, ip string, mark string, port string) (interface{}, error) {

	if d.mode != constants.LocalContainer {
		ip = DefaultNetwork
	}

	pu, err := d.puTracker.Get(ip)
	if err == nil {
		return pu, err
	}

	if app {
		markKey := "mark:" + mark + "$"
		pu, err = d.puTracker.Get(markKey)
		if err != nil {
			return nil, fmt.Errorf("PU context cannot be found using ip %v mark %v mode %v", ip, markKey, d.mode)
		}
		return pu, nil
	}

	portKey := "port:" + port
	pu, err = d.puTracker.Get(portKey)
	if err != nil {
		return nil, fmt.Errorf("PU Context cannot be found using ip %v port key %v mode %v", ip, portKey, d.mode)
	}
	return pu, nil
}
