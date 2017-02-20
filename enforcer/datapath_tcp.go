package enforcer

// Go libraries
import (
	"bytes"
	"fmt"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
)

// processNetworkPackets processes packets arriving from network and are destined to the application
func (d *datapathEnforcer) processNetworkTCPPackets(p *packet.Packet) error {

	// Skip SynAck packets that we haven't seen a connection
	if d.mode != constants.LocalContainer && p.L4TCPPacket.TCPFlags == packet.TCPSynAckMask {
		if _, err := d.sourcePortCache.Get(p.SynAckNetworkHash()); err != nil {
			return nil
		}
	}

	d.netTCP.IncomingPackets++
	p.Print(packet.PacketStageIncoming)

	if d.service != nil {
		if !d.service.PreProcessTCPNetPacket(p) {
			d.netTCP.ServicePreDropPackets++
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
		d.netTCP.AuthDropPackets++
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
			d.netTCP.ServicePostDropPackets++
			p.Print(packet.PacketFailureService)

			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Debug("Post service processing failed for network packet")
			return fmt.Errorf("Post service processing failed")
		}
	}

	// Accept the packet
	d.netTCP.OutgoingPackets++
	p.Print(packet.PacketStageOutgoing)
	return nil
}

// processApplicationPackets processes packets arriving from an application and are destined to the network
func (d *datapathEnforcer) processApplicationTCPPackets(p *packet.Packet) error {

	// Skip SynAck packets for connections that we are not processing
	if d.mode != constants.LocalContainer && p.L4TCPPacket.TCPFlags == packet.TCPSynAckMask {
		if _, err := d.destinationPortCache.Get(p.SynAckApplicationHash()); err != nil {
			return nil
		}
	}

	d.appTCP.IncomingPackets++
	p.Print(packet.PacketStageIncoming)

	if d.service != nil {
		// PreProcessServiceInterface
		if !d.service.PreProcessTCPAppPacket(p) {
			d.appTCP.ServicePreDropPackets++
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
		d.appTCP.AuthDropPackets++
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
			d.appTCP.ServicePostDropPackets++
			p.Print(packet.PacketFailureService)

			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Debug("Post service processing failed for application packet")
			return fmt.Errorf("Post service processing failed")
		}
	}

	// Accept the packet
	d.appTCP.OutgoingPackets++
	p.Print(packet.PacketStageOutgoing)
	return nil
}

func (d *datapathEnforcer) createTCPAuthenticationOption(token []byte, tcpPacket *packet.Packet) []byte {

	tokenLen := uint8(len(token))
	options := []byte{packet.TCPFastopenCookie, 2 + tokenLen}
	options = append(options, token...)
	for i := 0; i < int(2)-1; i++ {
		options = append(options, 0)
	}
	for (len(tcpPacket.GetTCPOptions())+len(options))%4 != 0 {
		options = append(options, 0)
	}

	tcpPacket.AppendOption(options)
	return options
}

func (d *datapathEnforcer) parseAckToken(connection *AuthInfo, data []byte) (*tokens.ConnectionClaims, error) {

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
func (d *datapathEnforcer) processApplicationSynPacket(tcpPacket *packet.Packet) (interface{}, error) {

	var connection *TCPConnection

	// Find the container context
	context, cerr := d.contextFromIP(true, tcpPacket.SourceAddress.String(), tcpPacket.Mark, strconv.Itoa(int(tcpPacket.L4TCPPacket.DestinationPort)))

	if cerr != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   cerr.Error(),
		}).Debug("Context not found for application syn packet")
		return nil, nil
	}

	existing, err := d.appConnectionTracker.Get(tcpPacket.L4FlowHash())
	if err == nil {
		connection = existing.(*TCPConnection)
	} else {
		connection = NewTCPConnection()
		connection.Auth.RemoteIP = tcpPacket.DestinationAddress.String()
		connection.Auth.RemotePort = strconv.Itoa(int(tcpPacket.L4TCPPacket.DestinationPort))
	}

	// Create TCP Option
	d.createTCPAuthenticationOption([]byte{}, tcpPacket)

	// Create a token
	tcpData := d.createPacketToken(false, context.(*PUContext), &connection.Auth)

	// Track the connection
	connection.State = TCPSynSend
	d.appConnectionTracker.AddOrUpdate(tcpPacket.L4FlowHash(), connection)
	d.contextConnectionTracker.AddOrUpdate(string(connection.Auth.LocalContext), connection)

	portHash := tcpPacket.SourceAddress.String() + ":" + strconv.Itoa(int(tcpPacket.L4TCPPacket.SourcePort))
	d.sourcePortCache.AddOrUpdate(portHash, context)
	if err = d.ProcessTCPFastOpen(tcpPacket); err != nil {
		//TCPFastopen returned an error drop the packet by returning an error here
		//The stack will try again with fastopen disabled
		return nil, err
	}
	// Attach the tags to the packet. We use a trick to reduce the seq number from ISN so that when our component gets out of the way, the
	// sequence numbers between the TCP stacks automatically match
	tcpPacket.DecreaseTCPSeq(uint32(len(tcpData)-1) + (d.ackSize))
	tcpPacket.TCPDataAttach(tcpData)

	tcpPacket.UpdateTCPChecksum()
	return nil, nil
}

func (d *datapathEnforcer) processApplicationSynAckPacket(tcpPacket *packet.Packet) (interface{}, error) {
	var context interface{}
	var err error

	if d.mode != constants.LocalContainer && tcpPacket.L4TCPPacket.TCPFlags == packet.TCPSynAckMask {
		if context, err = d.destinationPortCache.Get(tcpPacket.SynAckApplicationHash()); err != nil {
			return nil, err
		}
	} else {
		context, err = d.contextFromIP(true, tcpPacket.SourceAddress.String(), tcpPacket.Mark, strconv.Itoa(int(tcpPacket.L4TCPPacket.DestinationPort)))
	}

	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Debug("Container not found for application syn ack packet")
		return nil, nil
	}

	// Create the reverse hash since we have cached based on the SYN and
	// Retrieve the connection context
	c, err := d.networkConnectionTracker.Get(tcpPacket.L4ReverseFlowHash())
	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Debug("Connection not found for application syn ack packet")
		return nil, nil
	}

	connection := c.(*TCPConnection)

	// Process the packet if I am the right state. I should have either received a Syn packet or
	// I could have send a SynAck and this is a duplicate request since my response was lost.
	if connection.State == TCPSynReceived || connection.State == TCPSynAckSend {

		connection.State = TCPSynAckSend

		// Create TCP Option
		d.createTCPAuthenticationOption([]byte{}, tcpPacket)

		// Create a token
		tcpData := d.createPacketToken(false, context.(*PUContext), &connection.Auth)
		if err = d.ProcessTCPFastOpen(tcpPacket); err != nil {
			//TCPFastopen returned an error drop the packet by returning an error here
			//The stack will try again with fastopen disabled
			return nil, err
		}
		// Attach the tags to the packet
		tcpPacket.DecreaseTCPSeq(uint32(len(tcpData) - 1))
		tcpPacket.DecreaseTCPAck(d.ackSize)
		tcpPacket.TCPDataAttach(tcpData)

		tcpPacket.UpdateTCPChecksum()
		return nil, nil
	}

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Error("Received SynACK in wrong state ")
	return nil, fmt.Errorf("Received SynACK in wrong state ")
}

func (d *datapathEnforcer) processApplicationAckPacket(tcpPacket *packet.Packet) (interface{}, error) {

	// Find the container context
	context, cerr := d.contextFromIP(true, tcpPacket.SourceAddress.String(), tcpPacket.Mark, strconv.Itoa(int(tcpPacket.L4TCPPacket.DestinationPort)))

	if cerr != nil {
		log.WithFields(log.Fields{
			"package":   "enforcer",
			"tcpPacket": tcpPacket,
			"error":     cerr,
		}).Debug("Container not found for application ack packet")
		return nil, nil
	}

	// Get the connection state. We need the state of the two random numbers
	c, err := d.appConnectionTracker.Get(tcpPacket.L4FlowHash())
	if err != nil {
		log.WithFields(log.Fields{
			"package":   "enforcer",
			"tcpPacket": tcpPacket,
			"error":     err,
		}).Debug("Connection not found for application ack packet")
		return nil, nil
	}

	connection := c.(*TCPConnection)

	// Only process in SynAckReceived state
	if connection.State == TCPSynAckReceived {
		// Create a new token that includes the source and destinatio nonse
		// These are both challenges signed by the secret key and random for every
		// connection minimizing the chances of a replay attack
		token := d.createPacketToken(true, context.(*PUContext), &connection.Auth)

		d.createTCPAuthenticationOption([]byte{}, tcpPacket)

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
		if err = d.ProcessTCPFastOpen(tcpPacket); err != nil {
			//TCPFastopen returned an error drop the packet by returning an error here
			//The stack will try again with fastopen disabled
			return nil, err
		}
		// Attach the tags to the packet
		tcpPacket.DecreaseTCPSeq(d.ackSize)
		tcpPacket.TCPDataAttach(token)
		tcpPacket.UpdateTCPChecksum()

		connection.State = TCPAckSend

		return nil, nil
	}

	// Catch the first request packet
	if connection.State == TCPAckSend {
		//Delete the state at this point .. There is a small chance that both packets are lost
		// and the other side will send us SYNACK again .. TBD if we need to change this
		d.contextConnectionTracker.Remove(connection.Auth.LocalContextID)
		d.appConnectionTracker.Remove(tcpPacket.L4FlowHash())
		return nil, nil
	}

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("Received application ACK packet in the wrong state")
	return nil, fmt.Errorf("Received application ACK packet in the wrong state! %v", connection.State)
}

func (d *datapathEnforcer) processApplicationTCPPacket(tcpPacket *packet.Packet) (interface{}, error) {

	// State machine based on the flags
	switch tcpPacket.L4TCPPacket.TCPFlags {
	case packet.TCPSynMask: //Processing SYN packet from Application
		action, err := d.processApplicationSynPacket(tcpPacket)
		return action, err

	case packet.TCPAckMask:
		action, err := d.processApplicationAckPacket(tcpPacket)
		return action, err

	case packet.TCPSynAckMask:
		action, err := d.processApplicationSynAckPacket(tcpPacket)
		return action, err
	default:
		return nil, nil
	}

}

func (d *datapathEnforcer) processNetworkSynPacket(context *PUContext, tcpPacket *packet.Packet) (interface{}, error) {

	var connection *TCPConnection

	// First check if a connection was previously established and this is a second SYNACK
	// packet. This means that our ACK packet was lost somewhere
	hash := tcpPacket.L4FlowHash()
	existing, err := d.networkConnectionTracker.Get(hash)
	if err == nil {
		connection = existing.(*TCPConnection)
	} else {
		connection = NewTCPConnection()
	}
	if err = d.ProcessTCPFastOpen(tcpPacket); err != nil {
		//TCPFastopen returned an error drop the packet by returning an error here
		//The stack will try again with fastopen disabled
		return nil, err
	}
	// Decode the JWT token using the context key
	// We need to add here to key renewal option where we decode with keys N, N-1
	// TBD

	claims, err := d.parsePacketToken(&connection.Auth, tcpPacket.GetTCPData())

	// If the token signature is not valid
	// We must drop the connection and we drop the Syn packet. The source will
	// retry but we have no state to maintain here.
	if err != nil || claims == nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Debug("Syn packet dropped because of invalid token")

		d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.InvalidToken, "", tcpPacket)
		return nil, fmt.Errorf("Syn packet dropped because of invalid token %v %+v", err, claims)
	}

	txLabel, ok := claims.T.Get(TransmitterLabel)
	if err := tcpPacket.CheckTCPAuthenticationOption(int(packet.TCPFastopenCookieBaseLen)); err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"txLabel": txLabel,
			"ok":      ok,
			"error":   err.Error(),
		}).Debug("TCP Authentication Option not found")

		d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.InvalidFormat, txLabel, tcpPacket)
		return nil, fmt.Errorf("TCP Authentication Option not found %v", err)
	}

	// Remove any of our data from the packet. No matter what we don't need the
	// metadata any more.
	tcpDataLen := uint32(tcpPacket.IPTotalLength - tcpPacket.TCPDataStartBytes())
	tcpPacket.IncreaseTCPSeq((tcpDataLen - 1) + (d.ackSize))
	if err := tcpPacket.TCPDataDetach(uint16(tcpPacket.TCPDataOffset()*4 - 20)); err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"txLabel": txLabel,
			"ok":      ok,
			"error":   err.Error(),
		}).Debug("Syn packet dropped because of invalid format")

		d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.InvalidFormat, txLabel, tcpPacket)
		return nil, fmt.Errorf("Syn packet dropped because of invalid format %v", err)
	}

	tcpPacket.DropDetachedBytes()
	tcpPacket.UpdateTCPChecksum()

	// Add the port as a label with an @ prefix. These labels are invalid otherwise
	// If all policies are restricted by port numbers this will allow port-specific policies
	claims.T.Add(PortNumberLabelString, strconv.Itoa(int(tcpPacket.L4TCPPacket.DestinationPort)))

	// Validate against reject rules first - We always process reject with higher priority
	if index, _ := context.rejectRcvRules.Search(claims.T); index >= 0 {
		// Reject the connection
		log.WithFields(log.Fields{
			"package": "enforcer",
			"claims":  fmt.Sprintf("%+v", claims.T),
			"context": context.ID,
			"rules":   fmt.Sprintf("%+v", context.rejectRcvRules),
		}).Debug("Syn packet - rejected because of deny policy")

		d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.PolicyDrop, txLabel, tcpPacket)

		return nil, fmt.Errorf("Connection rejected because of policy %+v", claims.T)
	}

	// Search the policy rules for a matching rule.
	if index, action := context.acceptRcvRules.Search(claims.T); index >= 0 {

		hash := tcpPacket.L4FlowHash()

		// Update the connection state and store the Nonse send to us by the host.
		// We use the nonse in the subsequent packets to achieve randomization.

		connection.State = TCPSynReceived

		// Note that if the connection exists already we will just end-up replicating it. No
		// harm here.
		d.networkConnectionTracker.AddOrUpdate(hash, connection)
		portHash := tcpPacket.DestinationAddress.String() + ":" + strconv.Itoa(int(tcpPacket.L4TCPPacket.DestinationPort)) + ":" + strconv.Itoa(int(tcpPacket.L4TCPPacket.SourcePort))
		d.destinationPortCache.AddOrUpdate(portHash, context)

		// Accept the connection
		return action, nil
	}

	d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.PolicyDrop, txLabel, tcpPacket)

	// Reject all other connections
	log.WithFields(log.Fields{
		"package": "enforcer",
		"claims":  fmt.Sprintf("%+v", claims.T),
		"context": context.ID,
	}).Debug("Syn packet - no matched tags - reject")

	return nil, fmt.Errorf("No matched tags - reject %+v", claims.T)
}

func (d *datapathEnforcer) processNetworkSynAckPacket(context *PUContext, tcpPacket *packet.Packet) (interface{}, error) {

	// First we need to receover our state of the connection. If we don't have any state
	// we drop the packets and the connections
	// connection, err := d.appConnectionTracker.Get(tcpPacket.L4ReverseFlowHash())
	tcpData := tcpPacket.GetTCPData()
	if len(tcpData) == 0 {
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Debug("SynAck packet dropped because of missing token.")

		d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.MissingToken, "", tcpPacket)
		return nil, fmt.Errorf("SynAck packet dropped because of missing token")
	}

	// Validate the certificate and parse the token
	claims, cert := d.tokenEngine.Decode(false, tcpData, nil)
	if claims == nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Debug("Synack  packet dropped because of bad claims")

		d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.MissingToken, "", tcpPacket)
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

	c, err := d.contextConnectionTracker.Get(string(claims.RMT))
	if err != nil {
		d.contextConnectionTracker.DumpStore()
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Debug("Synack, no connection found for the claims")
		return nil, fmt.Errorf("No connection found for %v", claims.RMT)
	}

	connection := c.(*TCPConnection)

	// Stash connection
	connection.Auth.RemotePublicKey = cert
	connection.Auth.RemoteContext = claims.LCL
	connection.Auth.RemoteContextID = remoteContextID
	tcpPacket.ConnectionMetadata = &connection.Auth

	if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Debug("Synack, TCP Authentication Option not found")

		d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.InvalidFormat, remoteContextID, tcpPacket)
		return nil, fmt.Errorf("TCP Authentication Option not found")
	}
	if err = d.ProcessTCPFastOpen(tcpPacket); err != nil {
		//TCPFastopen returned an error drop the packet by returning an error here
		//The stack will try again with fastopen disabled
		return nil, err
	}
	// Remove any of our data
	tcpDataLen := uint32(tcpPacket.IPTotalLength - tcpPacket.TCPDataStartBytes())
	tcpPacket.IncreaseTCPSeq(tcpDataLen - 1)
	tcpPacket.IncreaseTCPAck(d.ackSize)

	if err := tcpPacket.TCPDataDetach(uint16(tcpPacket.TCPDataOffset()*4 - 20)); err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Debug("SynAck packet dropped because of invalid format")
		d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.InvalidFormat, remoteContextID, tcpPacket)
		return nil, fmt.Errorf("SynAck packet dropped because of invalid format")
	}

	tcpPacket.DropDetachedBytes()
	tcpPacket.UpdateTCPChecksum()

	// We can now verify the reverse policy. The system requires that policy
	// is matched in both directions. We have to make this optional as it can
	// become a very strong condition

	// First validate that there are no reject rules
	if index, _ := context.rejectTxtRules.Search(claims.T); d.mutualAuthorization && index >= 0 {
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Error("Dropping because of txt rules instruction")
		d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.PolicyDrop, remoteContextID, tcpPacket)
		return nil, fmt.Errorf("Dropping because of reject rule on transmitter")
	}

	if index, action := context.acceptTxtRules.Search(claims.T); !d.mutualAuthorization || index >= 0 {
		connection.State = TCPSynAckReceived
		return action, nil
	}

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Error("Dropping packet SYNACK at the network")

	d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.PolicyDrop, remoteContextID, tcpPacket)
	return nil, fmt.Errorf("Dropping packet SYNACK at the network ")
}

func (d *datapathEnforcer) processNetworkAckPacket(context *PUContext, tcpPacket *packet.Packet) (interface{}, error) {

	log.WithFields(log.Fields{
		"package": "enforcer",
	}).Debug("Process network Ack packet")

	// Retrieve connection context
	hash := tcpPacket.L4FlowHash()
	c, err := d.networkConnectionTracker.Get(hash)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
		}).Debug("Ignore the packet")
		return nil, nil
	}

	connection := c.(*TCPConnection)

	// Validate that the source/destination nonse matches. The signature has validated both directions
	if connection.State == TCPSynAckSend {

		if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); err != nil {
			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Error("TCP Authentication Option not found")

			d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.InvalidFormat, "", tcpPacket)
			return nil, fmt.Errorf("TCP Authentication Option not found")
		}

		if _, err := d.parseAckToken(&connection.Auth, tcpPacket.GetTCPData()); err != nil {
			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Error("Ack packet dropped because singature validation failed")

			d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.InvalidFormat, "", tcpPacket)
			return nil, fmt.Errorf("Ack packet dropped because singature validation failed %v", err)
		}
		if err = d.ProcessTCPFastOpen(tcpPacket); err != nil {
			//TCPFastopen returned an error drop the packet by returning an error here
			//The stack will try again with fastopen disabled
			return nil, err
		}
		connection.State = TCPAckProcessed

		// Remove any of our data
		tcpPacket.IncreaseTCPSeq(d.ackSize)
		err := tcpPacket.TCPDataDetach(uint16(tcpPacket.TCPDataOffset()*4 - 20))

		if err != nil {
			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Error("Ack packet dropped because of invalid format")
			d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.InvalidFormat, "", tcpPacket)
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
		d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowAccept, "NA", connection.Auth.RemoteContextID, tcpPacket)

		// Accept the packet
		return nil, nil

	}

	// Catch the first request packets
	if connection.State == TCPAckProcessed {
		// Safe to delete the state
		d.networkConnectionTracker.Remove(hash)
		return nil, nil
	}

	// Everything else is dropped
	d.collector.CollectFlowEvent(context.ID, context.Annotations, collector.FlowReject, collector.InvalidState, "", tcpPacket)
	return nil, fmt.Errorf("Ack packet dropped - no matching rules")
}

func (d *datapathEnforcer) processNetworkTCPPacket(tcpPacket *packet.Packet) (interface{}, error) {

	var err error
	var context interface{}

	if d.mode != constants.LocalContainer && tcpPacket.L4TCPPacket.TCPFlags == packet.TCPSynAckMask {
		if context, err = d.sourcePortCache.Get(tcpPacket.SynAckNetworkHash()); err != nil {
			return nil, nil
		}
	} else {
		// Lookup the policy rules for the packet - Return false if they don't exist
		context, err = d.contextFromIP(false, tcpPacket.DestinationAddress.String(), tcpPacket.Mark, strconv.Itoa(int(tcpPacket.L4TCPPacket.DestinationPort)))
		if err != nil && d.service != nil && tcpPacket.L4TCPPacket.TCPFlags&packet.TCPSynMask == 0 {
			return nil, nil
		}
	}

	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcer",
			"error":   err.Error(),
		}).Error("Process network TCP packet: Failed to retrieve context for this packet")
		return nil, fmt.Errorf("Context not found for container %s %v", tcpPacket.DestinationAddress.String(), d.puTracker)
	}

	// Update connection state in the internal state machine tracker
	switch tcpPacket.L4TCPPacket.TCPFlags {

	case packet.TCPSynMask:
		return d.processNetworkSynPacket(context.(*PUContext), tcpPacket)

	case packet.TCPAckMask:
		return d.processNetworkAckPacket(context.(*PUContext), tcpPacket)

	case packet.TCPSynAckMask:
		return d.processNetworkSynAckPacket(context.(*PUContext), tcpPacket)

	default: // Ignore any other packet
		return nil, nil
	}
}

func (d *datapathEnforcer) ProcessTCPFastOpen(tcpPacket *packet.Packet) error {
	/*
		var cacheKey string
		if tcpPacket.GetProcessingStage() == packet.PacketTypeApplication {
			cacheKey = tcpPacket.DestinationAddress.String()
		} else {
			cacheKey = tcpPacket.SourceAddress.String()
		}
		//Lets update the fast open cookie cache here
		optionval, present := tcpPacket.TCPOptionData(packet.TCPFastopenCookie)

		if present { //option is present on the packet
			fmt.Println("%%%%%%%%%%%%%%%%%%%%%%%%%%")
			fmt.Println("Processing Stage", tcpPacket.GetProcessingStage())
			fmt.Println("IP Address", tcpPacket.DestinationAddress.String())
			fmt.Println("Found Fast Open option with cookie $$$$", optionval)
			fmt.Println("%%%%%%%%%%%%%%%%%%%%%%%%%%")
			//We have a cookie in the syn packet going out
			//Check if we have seen this before if we have not drop the packet
			//The stack will retry with tcp fast open disabled

			if len(optionval) > 0 { //option is not empty. We should have seen this cookie before

				val, err := d.foCookieTracker.Get(cacheKey)
				//We have an unexpired cookie in our cache and client is sending a different cookie. Drop this packet
				if err != nil {
					return fmt.Errorf("Invalid fast open cookie")
				} else if err == nil && bytes.Compare(val.([]byte), optionval) != 0 {
					fmt.Println("Expect cookie val", val.([]byte))
					fmt.Println("Got Cookie ", optionval)
					return fmt.Errorf("Fast open cookie different")
				} else {
					//We have a valid cookie let this packet through
					if tcpPacket.GetProcessingStage() == packet.PacketTypeNetwork {
						//We received a packet from the network where the cookie does nto match.
						if len(val.([]byte)) == 0 {
							d.foCookieTracker.AddOrUpdate(cacheKey, optionval)
						} else {

						}
					}
					return nil
				}

			} else { //(len(optionval) ==  0
				//we have an empty cookie being sent just create a record in our cache and let it go
				d.foCookieTracker.Add(cacheKey, optionval)

			}

		} else {
			//If we are in network and the server did not respond with fast option enabled clear the cache for this entry. This server does not support fast open
			if tcpPacket.GetProcessingStage() == packet.PacketTypeNetwork {
				d.foCookieTracker.Remove(cacheKey)
			}
		}
		//The option is not present on the packet do nothing
	*/
	return nil
}
