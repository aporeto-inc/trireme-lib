package enforcer

// Go libraries
import (
	"fmt"
	"net"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer/lookup"
	"github.com/aporeto-inc/trireme/enforcer/netfilter"
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
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

	// stats
	net    *InterfaceStats
	app    *InterfaceStats
	netTCP *PacketStats
	appTCP *PacketStats

	// ack size
	ackSize uint32

	// remote indicates that this is a remote enforcer and it only processes one unit
	// As a result the enforcer will ignore IP addresses
	remote bool
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
	remote bool,
) PolicyEnforcer {

	tokenEngine, err := tokens.NewJWT(validity, serverID, secrets)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Fatal("Unable to create TokenEngine in enforcer")
	}

	d := &datapathEnforcer{
		contextTracker:           cache.NewCache(nil),
		puTracker:                cache.NewCache(nil),
		networkConnectionTracker: cache.NewCacheWithExpiration(time.Second * 60),
		appConnectionTracker:     cache.NewCacheWithExpiration(time.Second * 60),
		contextConnectionTracker: cache.NewCacheWithExpiration(time.Second * 60),
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
		remote:                   remote,
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
	remote bool,
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
		remote,
	)
}

func (d *datapathEnforcer) Enforce(contextID string, puInfo *policy.PUInfo) error {

	log.WithFields(log.Fields{
		"package":   "enforcer",
		"contextID": contextID,
	}).Debug("Enforce IP")

	ip, err := d.contextTracker.Get(contextID)

	if err != nil {
		return d.doCreatePU(contextID, puInfo)
	}

	puContext, err := d.puTracker.Get(ip)

	if err != nil {
		return d.doCreatePU(contextID, puInfo)
	}

	return d.doUpdatePU(puContext.(*PUContext), puInfo)
}

func (d *datapathEnforcer) doCreatePU(contextID string, puInfo *policy.PUInfo) error {

	ip := DefaultNetwork
	if !d.remote {
		if _, ok := puInfo.Policy.DefaultIPAddress(); !ok {
			return fmt.Errorf("No IP address found")
		}
		ip, _ = puInfo.Policy.DefaultIPAddress()
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("Invalid up address %s\n", ip)
		}
	}

	pu := &PUContext{
		ID: contextID,
	}

	d.doUpdatePU(pu, puInfo)
	d.contextTracker.AddOrUpdate(contextID, ip)
	d.puTracker.AddOrUpdate(ip, pu)

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

	ip, err := d.contextTracker.Get(contextID)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "enforcer",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("IP not found in Enforcer when unenforce")
		return fmt.Errorf("ContextID not found in Enforcer")
	}

	err = d.puTracker.Remove(ip)

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

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("process network packets from NFQ")

	d.net.IncomingPackets++

	// Parse the packet - drop if parsing fails
	netPacket, err := packet.New(packet.PacketTypeNetwork, p.Buffer)
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
	return
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
	appPacket, err := packet.New(packet.PacketTypeApplication, p.Buffer)

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

	return d.tokenEngine.CreateAndSign(ackToken, claims)
}

func (d *datapathEnforcer) parsePacketToken(auth *AuthInfo, data []byte) (*tokens.ConnectionClaims, error) {

	// Validate the certificate and parse the token
	claims, cert := d.tokenEngine.Decode(false, data, auth.RemotePublicKey)
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
func (d *datapathEnforcer) contextFromIP(ip string) (interface{}, error) {
	if d.remote {
		return d.puTracker.Get(DefaultNetwork)
	}
	return d.puTracker.Get(ip)
}
