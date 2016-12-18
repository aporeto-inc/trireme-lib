package enforcer

// Go libraries
import (
	"bytes"
	"fmt"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer/lookup"
	"github.com/aporeto-inc/trireme/enforcer/netfilter"
	"github.com/aporeto-inc/trireme/enforcer/packet"
	"github.com/aporeto-inc/trireme/enforcer/tokens"
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
	net *PacketStats
	app *PacketStats

	// ack size
	ackSize uint32
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
		networkConnectionTracker: cache.NewCacheWithExpiration(time.Second*60, 100000),
		appConnectionTracker:     cache.NewCacheWithExpiration(time.Second*60, 100000),
		contextConnectionTracker: cache.NewCacheWithExpiration(time.Second*60, 100000),
		filterQueue:              filterQueue,
		mutualAuthorization:      mutualAuth,
		service:                  service,
		collector:                collector,
		tokenEngine:              tokenEngine,
		net:                      &PacketStats{},
		app:                      &PacketStats{},
		ackSize:                  secrets.AckSize(),
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

	ip, ok := puInfo.Policy.DefaultIPAddress()
	if !ok {
		log.WithFields(log.Fields{
			"package":   "enforcer",
			"contextID": contextID,
		}).Debug("No Default IP for PU, not enforcing.")
		return fmt.Errorf("No Default IP for PU, not enforcing.")
	}

	//TODO: Add Check that IP is valid.
	pu := &PUContext{
		ID: contextID,
	}

	d.doUpdatePU(pu, puInfo)
	d.contextTracker.AddOrUpdate(contextID, ip)
	d.puTracker.AddOrUpdate(ip, pu)

	return nil
}

func (d *datapathEnforcer) doUpdatePU(puContext *PUContext, containerInfo *policy.PUInfo) error {

	rx := fmt.Sprintf("%+v", puContext.receiverRules)
	tx := fmt.Sprintf("%+v", puContext.transmitterRules)
	log.WithFields(log.Fields{
		"package":   "enforcer",
		"contextID": puContext.ID,
		"rxRules":   rx,
		"txRules":   tx,
	}).Debug("doUpdatePU Pre")

	puContext.receiverRules = createRuleDB(containerInfo.Policy.ReceiverRules())
	puContext.transmitterRules = createRuleDB(containerInfo.Policy.TransmitterRules())
	puContext.Tags = containerInfo.Policy.PolicyTags()

	rx = fmt.Sprintf("%+v", puContext.receiverRules)
	tx = fmt.Sprintf("%+v", puContext.transmitterRules)
	log.WithFields(log.Fields{
		"package":   "enforcer",
		"contextID": puContext.ID,
		"rxRules":   rx,
		"txRules":   tx,
	}).Debug("doUpdatePU Post")
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

func createRuleDB(policyRules *policy.TagSelectorList) *lookup.PolicyDB {

	rules := lookup.NewPolicyDB()
	for _, rule := range policyRules.TagSelectors {
		rules.AddPolicy(rule)
	}

	return rules
}

// processNetworkPacketsFromNFQ processes packets arriving from the network in an NF queue
func (d *datapathEnforcer) processNetworkPacketsFromNFQ(p *netfilter.NFPacket) {

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("process network packets from NFQ")

	d.net.IncomingPackets++

	// Parse the packet - drop if parsing fails
	tcpPacket, err := packet.New(packet.PacketTypeNetwork, p.Buffer)
	if err != nil {
		d.net.CreateDropPackets++
		tcpPacket.Print(packet.PacketFailureCreate)
	} else {
		err = d.processNetworkPackets(tcpPacket)
	}

	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Debug("Error when processing network packets from NFQ")

		netfilter.SetVerdict(&netfilter.Verdict{
			V:           netfilter.NfDrop,
			Buffer:      tcpPacket.Buffer,
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
		Buffer:      tcpPacket.Buffer,
		Payload:     tcpPacket.GetTCPData(),
		Options:     tcpPacket.GetTCPOptions(),
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
	tcpPacket, err := packet.New(packet.PacketTypeApplication, p.Buffer)

	if err != nil {
		d.app.CreateDropPackets++
		tcpPacket.Print(packet.PacketFailureCreate)
	} else {
		err = d.processApplicationPackets(tcpPacket)
	}

	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Debug("Error when processing application packets from NFQ")

		netfilter.SetVerdict(&netfilter.Verdict{
			V:           netfilter.NfDrop,
			Buffer:      tcpPacket.Buffer,
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
		Buffer:      tcpPacket.Buffer,
		Payload:     tcpPacket.GetTCPData(),
		Options:     tcpPacket.GetTCPOptions(),
		Xbuffer:     p.Xbuffer,
		ID:          p.ID,
		QueueHandle: p.QueueHandle,
	}, d.filterQueue.MarkValue)

}

// processNetworkPackets processes packets arriving from network and are destined to the application
func (d *datapathEnforcer) processNetworkPackets(p *packet.Packet) error {

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("process network packets")

	p.Print(packet.PacketStageIncoming)

	if d.service != nil {
		// PreProcessServiceInterface
		if !d.service.PreProcessTCPNetPacket(p) {
			d.net.ServicePreDropPackets++
			p.Print(packet.PacketFailureService)

			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Debug("Pre service processing failed for network packet")
			return fmt.Errorf("Pre service processing failed")
		}
	}

	p.Print(packet.PacketStageAuth)

	// Match the tags of the packet against the policy rules - drop if the lookup fails
	action, err := d.processNetworkTCPPacket(p)
	if err != nil {
		d.net.AuthDropPackets++
		p.Print(packet.PacketFailureAuth)

		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Debug("Service processing failed for network packet")
		return fmt.Errorf("Processing failed %v", err)
	}

	p.Print(packet.PacketStageService)

	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessTCPNetPacket(p, action) {
			d.net.ServicePostDropPackets++
			p.Print(packet.PacketFailureService)

			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Debug("Post service processing failed for network packet")
			return fmt.Errorf("Post service processing failed")
		}
	}

	// Accept the packet
	d.net.OutgoingPackets++
	p.Print(packet.PacketStageOutgoing)
	return nil
}

// processApplicationPackets processes packets arriving from an application and are destined to the network
func (d *datapathEnforcer) processApplicationPackets(p *packet.Packet) error {

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("process application packets")

	if d.service != nil {
		// PreProcessServiceInterface
		if !d.service.PreProcessTCPAppPacket(p) {
			d.app.ServicePreDropPackets++
			p.Print(packet.PacketFailureService)

			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Debug("Pre service processing failed for application packet")
			return fmt.Errorf("Pre service processing failed")
		}
	}

	p.Print(packet.PacketStageAuth)

	// Match the tags of the packet against the policy rules - drop if the lookup fails
	action, err := d.processApplicationTCPPacket(p)
	if err != nil {
		d.app.AuthDropPackets++
		p.Print(packet.PacketFailureAuth)

		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Debug("Processing failed for application packet")
		return fmt.Errorf("Processing failed %v", err)
	}

	p.Print(packet.PacketStageService)

	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessTCPAppPacket(p, action) {
			d.app.ServicePostDropPackets++
			p.Print(packet.PacketFailureService)

			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Debug("Post service processing failed for application packet")
			return fmt.Errorf("Post service processing failed")
		}
	}

	// Accept the packet
	d.app.OutgoingPackets++
	p.Print(packet.PacketStageOutgoing)
	return nil
}

func (d *datapathEnforcer) createTCPAuthenticationOption(token []byte) []byte {

	tokenLen := uint8(len(token))
	options := []byte{packet.TCPAuthenticationOption, TCPAuthenticationOptionBaseLen + tokenLen, 0, 0}

	if tokenLen != 0 {
		options = append(options, token...)
	}

	return options
}

func (d *datapathEnforcer) createPacketToken(ackToken bool, context *PUContext, connection *Connection) []byte {

	claims := &tokens.ConnectionClaims{
		LCL: connection.LocalContext,
		RMT: connection.RemoteContext,
	}

	if !ackToken {
		claims.T = context.Tags
	}

	return d.tokenEngine.CreateAndSign(ackToken, claims)
}

func (d *datapathEnforcer) parseAckToken(connection *Connection, data []byte) (*tokens.ConnectionClaims, error) {

	// Validate the certificate and parse the token
	claims, _ := d.tokenEngine.Decode(true, data, connection.RemotePublicKey)
	if claims == nil {
		return nil, fmt.Errorf("Cannot decode the token")
	}

	// Compare the incoming random context with the stored context
	matchLocal := bytes.Compare(claims.RMT, connection.LocalContext)
	matchRemote := bytes.Compare(claims.LCL, connection.RemoteContext)
	if matchLocal != 0 || matchRemote != 0 {
		return nil, fmt.Errorf("Failed to match context in ACK packet")
	}

	return claims, nil
}

func (d *datapathEnforcer) parsePacketToken(connection *Connection, data []byte) (*tokens.ConnectionClaims, error) {

	// Validate the certificate and parse the token
	claims, cert := d.tokenEngine.Decode(false, data, connection.RemotePublicKey)
	if claims == nil {
		return nil, fmt.Errorf("Cannot decode the token")
	}

	// We always a need a valid remote context ID
	remoteContextID, ok := claims.T.Get(TransmitterLabel)
	if !ok {
		return nil, fmt.Errorf("No Transmitter Label ")
	}

	connection.RemotePublicKey = cert
	connection.RemoteContext = claims.LCL
	connection.RemoteContextID = remoteContextID

	return claims, nil
}

func (d *datapathEnforcer) processApplicationSynPacket(tcpPacket *packet.Packet) (interface{}, error) {

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("process application syn packet")

	var connection *Connection

	// Find the container context
	context, cerr := d.puTracker.Get(tcpPacket.SourceAddress.String())

	if cerr != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   cerr.Error(),
		}).Debug("Container not found for application syn packet")
		return nil, nil
	}

	existing, err := d.appConnectionTracker.Get(tcpPacket.L4FlowHash())
	if err == nil {
		connection = existing.(*Connection)
	} else {
		connection = NewConnection()
		connection.RemoteIP = tcpPacket.DestinationAddress.String()
		connection.RemotePort = strconv.Itoa(int(tcpPacket.DestinationPort))
		log.WithFields(log.Fields{
			"package":    "enforcer",
			"remoteip":   connection.RemoteIP,
			"remoteport": connection.RemotePort,
		}).Debug("Connection not found, creating new connection")
	}

	// Create TCP Option
	tcpOptions := d.createTCPAuthenticationOption([]byte{})

	// Create a token
	tcpData := d.createPacketToken(false, context.(*PUContext), connection)

	// Track the connection
	connection.State = SynSend
	d.appConnectionTracker.AddOrUpdate(tcpPacket.L4FlowHash(), connection)
	d.contextConnectionTracker.AddOrUpdate(string(connection.LocalContext), connection)

	// Attach the tags to the packet. We use a trick to reduce the seq number from ISN so that when our component gets out of the way, the
	// sequence numbers between the TCP stacks automatically match
	tcpPacket.DecreaseTCPSeq(uint32(len(tcpData)-1) + (d.ackSize))
	tcpPacket.TCPDataAttach(tcpOptions, tcpData)

	tcpPacket.UpdateTCPChecksum()
	return nil, nil
}

func (d *datapathEnforcer) processApplicationSynAckPacket(tcpPacket *packet.Packet) (interface{}, error) {

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("process application syn ack packet")

	// Find the container context
	context, cerr := d.puTracker.Get(tcpPacket.SourceAddress.String())

	if cerr != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   cerr.Error(),
		}).Debug("Container not found for application syn ack packet")
		return nil, nil
	}

	// Create the reverse hash since we have cached based on the SYN and
	// Retrieve the connection context
	connection, err := d.networkConnectionTracker.Get(tcpPacket.L4ReverseFlowHash())
	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Debug("Connection not found for application syn ack packet")
		return nil, nil
	}

	// Process the packet if I am the right state. I should have either received a Syn packet or
	// I could have send a SynAck and this is a duplicate request since my response was lost.
	if connection.(*Connection).State == SynReceived || connection.(*Connection).State == SynAckSend {

		connection.(*Connection).State = SynAckSend

		// Create TCP Option
		tcpOptions := d.createTCPAuthenticationOption([]byte{})

		// Create a token
		tcpData := d.createPacketToken(false, context.(*PUContext), connection.(*Connection))

		// Attach the tags to the packet
		tcpPacket.DecreaseTCPSeq(uint32(len(tcpData) - 1))
		tcpPacket.DecreaseTCPAck(d.ackSize)
		tcpPacket.TCPDataAttach(tcpOptions, tcpData)

		tcpPacket.UpdateTCPChecksum()
		return nil, nil
	}

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Error("Received SynACK in wrong state ")
	return nil, fmt.Errorf("Received SynACK in wrong state ")
}

func (d *datapathEnforcer) processApplicationAckPacket(tcpPacket *packet.Packet) (interface{}, error) {

	log.WithFields(log.Fields{
		"package":   "enforcer",
		"tcpPacket": tcpPacket,
	}).Debug("process application ack packet")

	// Find the container context
	context, cerr := d.puTracker.Get(tcpPacket.SourceAddress.String())

	if cerr != nil {
		log.WithFields(log.Fields{
			"package":   "enforcer",
			"tcpPacket": tcpPacket,
			"error":     cerr,
		}).Debug("Container not found for application ack packet")
		return nil, nil
	}

	// Get the connection state. We need the state of the two random numbers
	connection, err := d.appConnectionTracker.Get(tcpPacket.L4FlowHash())

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "enforcer",
			"tcpPacket": tcpPacket,
			"error":     err,
		}).Debug("Connection not found for application ack packet")
		return nil, nil
	}

	// Only process in SynAckReceived state
	if connection.(*Connection).State == SynAckReceived {
		// Create a new token that includes the source and destinatio nonse
		// These are both challenges signed by the secret key and random for every
		// connection minimizing the chances of a replay attack
		token := d.createPacketToken(true, context.(*PUContext), connection.(*Connection))

		tcpOptions := d.createTCPAuthenticationOption([]byte{})

		if len(token) != int(d.ackSize) {
			log.WithFields(log.Fields{
				"package":     "enforcer",
				"tcpPacket":   tcpPacket,
				"tokenLength": len(token),
				"connection":  connection,
				"ackSize":     int(d.ackSize),
			}).Error("Protocol error for application ack packet")
			return nil, fmt.Errorf("Protocol Error %d", len(token))
		}

		// Attach the tags to the packet
		tcpPacket.DecreaseTCPSeq(d.ackSize)
		tcpPacket.TCPDataAttach(tcpOptions, token)
		tcpPacket.UpdateTCPChecksum()

		connection.(*Connection).State = AckSend

		return nil, nil
	}

	// Catch the first request packet
	if connection.(*Connection).State == AckSend {
		//Delete the state at this point .. There is a small chance that both packets are lost
		// and the other side will send us SYNACK again .. TBD if we need to change this
		d.contextConnectionTracker.Remove(connection.(*Connection).LocalContextID)
		d.appConnectionTracker.Remove(tcpPacket.L4FlowHash())
		return nil, nil
	}

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("Received application ACK packet in the wrong state")
	return nil, fmt.Errorf("Received application ACK packet in the wrong state! %v", connection.(*Connection).State)
}

func (d *datapathEnforcer) processApplicationTCPPacket(tcpPacket *packet.Packet) (interface{}, error) {

	log.WithFields(log.Fields{
		"package":   "enforcer",
		"tcpPacket": tcpPacket,
	}).Debug("process application TCP packet")

	// Initialize payload and options buffer with our new TCP options. Currenty using
	// the experimental option and padding the packet with two data fields to make
	// a 32-bit alignment. We have to use these data actually rather then send 0s.

	// State machine based on the flags
	switch tcpPacket.TCPFlags {
	case packet.TCPSynMask: //Processing SYN packet from Application
		action, err := d.processApplicationSynPacket(tcpPacket)
		return action, err

	case packet.TCPAckMask:
		action, err := d.processApplicationAckPacket(tcpPacket)
		return action, err

	case packet.TCPSynAckMask:
		action, err := d.processApplicationSynAckPacket(tcpPacket)
		return action, err
	}

	return nil, nil
}

func (d *datapathEnforcer) processNetworkSynPacket(context *PUContext, tcpPacket *packet.Packet) (interface{}, error) {

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("Process network Syn packet")

	var connection *Connection
	// First check if a connection was previously established and this is a second SYNACK
	// packet. This means that our ACK packet was lost somewhere
	hash := tcpPacket.L4FlowHash()
	existing, err := d.networkConnectionTracker.Get(hash)

	if err == nil {
		connection = existing.(*Connection)
	} else {
		connection = NewConnection()
	}

	// Decode the JWT token using the context key
	// We need to add here to key renewal option where we decode with keys N, N-1
	// TBD
	claims, err := d.parsePacketToken(connection, tcpPacket.ReadTCPData())

	// If the token signature is not valid
	// We must drop the connection and we drop the Syn packet. The source will
	// retry but we have no state to maintain here.
	if err != nil || claims == nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Debug("Syn packet dropped because of invalid token")

		d.collector.CollectFlowEvent(context.ID, context.Tags, collector.FlowReject, collector.InvalidToken, "", tcpPacket)
		return nil, fmt.Errorf("Syn packet dropped because of invalid token %v %+v", err, claims)
	}

	txLabel, ok := claims.T.Get(TransmitterLabel)
	if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"txLabel": txLabel,
			"ok":      ok,
			"error":   err.Error(),
		}).Debug("TCP Authentication Option not found")

		d.collector.CollectFlowEvent(context.ID, context.Tags, collector.FlowReject, collector.InvalidFormat, txLabel, tcpPacket)
		return nil, fmt.Errorf("TCP Authentication Option not found %v", err)
	}

	// Remove any of our data from the packet. No matter what we don't need the
	// metadata any more.
	tcpDataLen := uint32(tcpPacket.IPTotalLength - tcpPacket.TCPDataStartBytes())
	tcpPacket.IncreaseTCPSeq((tcpDataLen - 1) + (d.ackSize))

	if err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen); err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"txLabel": txLabel,
			"ok":      ok,
			"error":   err.Error(),
		}).Debug("Syn packet dropped because of invalid format")

		d.collector.CollectFlowEvent(context.ID, context.Tags, collector.FlowReject, collector.InvalidFormat, txLabel, tcpPacket)
		return nil, fmt.Errorf("Syn packet dropped because of invalid format %v", err)
	}

	tcpPacket.DropDetachedBytes()
	tcpPacket.UpdateTCPChecksum()

	// Add the port as a label with an @ prefix. These labels are invalid otherwise
	// If all policies are restricted by port numbers this will allow port-specific policies
	claims.T.Add(PortNumberLabelString, strconv.Itoa(int(tcpPacket.DestinationPort)))

	// Search the policy rules for a matching rule.
	if index, action := context.receiverRules.Search(claims.T); index >= 0 {

		hash := tcpPacket.L4FlowHash()

		// Update the connection state and store the Nonse send to us by the host.
		// We use the nonse in the subsequent packets to achieve randomization.

		connection.State = SynReceived

		// Note that if the connection exists already we will just end-up replicating it. No
		// harm here.
		d.networkConnectionTracker.AddOrUpdate(hash, connection)

		// Accept the connection
		return action, nil
	}

	d.collector.CollectFlowEvent(context.ID, context.Tags, collector.FlowReject, collector.PolicyDrop, txLabel, tcpPacket)

	// Reject all other connections
	c := fmt.Sprintf("%+v", claims.T)
	r := fmt.Sprintf("%+v", context.receiverRules)
	log.WithFields(log.Fields{
		"package": "enforcer",
		"claims":  c,
		"context": context.ID,
		"rules":   r,
	}).Debug("Syn packet - no matched tags - reject")

	return nil, fmt.Errorf("No matched tags - reject %+v", claims.T)
}

func (d *datapathEnforcer) processNetworkSynAckPacket(context *PUContext, tcpPacket *packet.Packet) (interface{}, error) {

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("Process network Syn Ack packet")

	// First we need to receover our state of the connection. If we don't have any state
	// we drop the packets and the connections
	// connection, err := d.appConnectionTracker.Get(tcpPacket.L4ReverseFlowHash())

	tcpData := tcpPacket.ReadTCPData()
	if len(tcpData) == 0 {
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Debug("SynAck packet dropped because of missing token.")

		d.collector.CollectFlowEvent(context.ID, context.Tags, collector.FlowReject, collector.MissingToken, "", tcpPacket)
		return nil, fmt.Errorf("SynAck packet dropped because of missing token.")
	}

	// Validate the certificate and parse the token
	claims, cert := d.tokenEngine.Decode(false, tcpData, nil)
	if claims == nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Debug("Synack  packet dropped because of bad claims")

		d.collector.CollectFlowEvent(context.ID, context.Tags, collector.FlowReject, collector.MissingToken, "", tcpPacket)
		return nil, fmt.Errorf("Synack  packet dropped because of bad claims %v", claims)
	}

	// We always a need a valid remote context ID
	remoteContextID, ok := claims.T.Get(TransmitterLabel)
	if !ok {
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Debug("Synack, no remote context for the claims")
		return nil, fmt.Errorf("No remote context %v", claims.T)
	}

	connection, err := d.contextConnectionTracker.Get(string(claims.RMT))
	if err != nil {
		d.contextConnectionTracker.DumpStore()
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Debug("Synack, no connection found for the claims")
		return nil, fmt.Errorf("No connection found for %v", claims.RMT)
	}

	// Stash connection
	tcpPacket.ConnectionMetadata = connection.(*Connection)

	connection.(*Connection).RemotePublicKey = cert
	connection.(*Connection).RemoteContext = claims.LCL
	connection.(*Connection).RemoteContextID = remoteContextID

	if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Debug("Synack, TCP Authentication Option not found")

		d.collector.CollectFlowEvent(context.ID, context.Tags, collector.FlowReject, collector.InvalidFormat, remoteContextID, tcpPacket)
		return nil, fmt.Errorf("TCP Authentication Option not found")
	}

	// Remove any of our data
	tcpDataLen := uint32(tcpPacket.IPTotalLength - tcpPacket.TCPDataStartBytes())
	tcpPacket.IncreaseTCPSeq(tcpDataLen - 1)
	tcpPacket.IncreaseTCPAck(d.ackSize)

	if err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen); err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Debug("SynAck packet dropped because of invalid format")
		d.collector.CollectFlowEvent(context.ID, context.Tags, collector.FlowReject, collector.InvalidFormat, remoteContextID, tcpPacket)
		return nil, fmt.Errorf("SynAck packet dropped because of invalid format")
	}

	tcpPacket.DropDetachedBytes()
	tcpPacket.UpdateTCPChecksum()

	// We can now verify the reverse policy. The system requires that policy
	// is matched in both directions. We have to make this optional as it can
	// become a very strong condition

	if index, action := context.transmitterRules.Search(claims.T); !d.mutualAuthorization || index >= 0 {
		connection.(*Connection).State = SynAckReceived
		return action, nil
	}

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Error("Dropping packet SYNACK at the network")

	d.collector.CollectFlowEvent(context.ID, context.Tags, collector.FlowReject, collector.PolicyDrop, remoteContextID, tcpPacket)
	return nil, fmt.Errorf("Dropping packet SYNACK at the network ")
}

func (d *datapathEnforcer) processNetworkAckPacket(context *PUContext, tcpPacket *packet.Packet) (interface{}, error) {

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("Process network Ack packet")

	// Retrieve connection context
	hash := tcpPacket.L4FlowHash()
	connection, err := d.networkConnectionTracker.Get(hash)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Debug("Ignore the packet")
		return nil, nil
	}

	// Validate that the source/destination nonse matches. The signature has validated both directions
	if connection.(*Connection).State == SynAckSend {

		if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); err != nil {
			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Error("TCP Authentication Option not found")

			d.collector.CollectFlowEvent(context.ID, context.Tags, collector.FlowReject, collector.InvalidFormat, "", tcpPacket)
			return nil, fmt.Errorf("TCP Authentication Option not found")
		}

		if _, err := d.parseAckToken(connection.(*Connection), tcpPacket.ReadTCPData()); err != nil {
			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Error("Ack packet dropped because singature validation failed")

			d.collector.CollectFlowEvent(context.ID, context.Tags, collector.FlowReject, collector.InvalidFormat, "", tcpPacket)
			return nil, fmt.Errorf("Ack packet dropped because singature validation failed %v", err)
		}

		connection.(*Connection).State = AckProcessed
		// Remove any of our data
		tcpPacket.IncreaseTCPSeq(d.ackSize)
		err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen)

		if err != nil {
			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Error("Ack packet dropped because of invalid format")
			d.collector.CollectFlowEvent(context.ID, context.Tags, collector.FlowReject, collector.InvalidFormat, "", tcpPacket)
			return nil, fmt.Errorf("Ack packet dropped because of invalid format %v", err)
		}

		tcpPacket.DropDetachedBytes()

		tcpPacket.UpdateTCPChecksum()

		// Delete the state
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Debug("processApplicationAckPacket() Connection Removed")

		d.networkConnectionTracker.Remove(hash)

		// We accept the packet as a new flow
		d.collector.CollectFlowEvent(context.ID, context.Tags, collector.FlowAccept, "NA", connection.(*Connection).RemoteContextID, tcpPacket)

		// Accept the packet
		return nil, nil

	}

	// Catch the first request packets
	if connection.(*Connection).State == AckProcessed {
		// Safe to delete the state
		d.networkConnectionTracker.Remove(hash)
		return nil, nil
	}

	// Everything else is dropped
	d.collector.CollectFlowEvent(context.ID, context.Tags, collector.FlowReject, collector.InvalidState, "", tcpPacket)
	return nil, fmt.Errorf("Ack packet dropped - no matching rules")
}

func (d *datapathEnforcer) processNetworkTCPPacket(tcpPacket *packet.Packet) (interface{}, error) {

	// Lookup the policy rules for the packet - Return false if they don't exist
	context, err := d.puTracker.Get(tcpPacket.DestinationAddress.String())

	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Debug("Process network TCP packet: Failed to retrieve context for this packet")
		return nil, fmt.Errorf("Context not found for container %s %v", tcpPacket.DestinationAddress.String(), d.puTracker)
	}

	log.WithFields(log.Fields{
		"package": "enforcer",
		"ip":      tcpPacket.DestinationAddress.String(),
		"context": context.(*PUContext).ID,
	}).Debug("Process network TCP packet")

	// Update connection state in the internal state machine tracker
	switch tcpPacket.TCPFlags {

	case packet.TCPSynMask:
		action, err := d.processNetworkSynPacket(context.(*PUContext), tcpPacket)
		return action, err

	case packet.TCPAckMask:
		action, err := d.processNetworkAckPacket(context.(*PUContext), tcpPacket)
		return action, err

	case packet.TCPSynAckMask:
		action, err := d.processNetworkSynAckPacket(context.(*PUContext), tcpPacket)
		return action, err

	default: // Ignore any other packet
		return nil, nil
	}
}
