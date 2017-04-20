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
	if d.mode != constants.LocalContainer && p.TCPFlags == packet.TCPSynAckMask {
		if _, err := d.sourcePortCache.Get(p.L4ReverseFlowHash()); err != nil {
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
		}).Debug("Packet processing failed for network packet")
		return err
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
	if d.mode != constants.LocalContainer && p.TCPFlags == packet.TCPSynAckMask {
		if _, err := d.destinationPortCache.Get(p.L4ReverseFlowHash()); err != nil {
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
		return err
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

func (d *datapathEnforcer) createTCPAuthenticationOption(token []byte) []byte {

	tokenLen := uint8(len(token))
	options := []byte{packet.TCPAuthenticationOption, TCPAuthenticationOptionBaseLen + tokenLen, 0, 0}

	if tokenLen != 0 {
		options = append(options, token...)
	}

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
	context, cerr := d.contextFromIP(true, tcpPacket.SourceAddress.String(), tcpPacket.Mark, strconv.Itoa(int(tcpPacket.DestinationPort)))
	if cerr != nil {
		return nil, nil
	}

	existing, err := d.appConnectionTracker.Get(tcpPacket.L4FlowHash())
	if err == nil {
		connection = existing.(*TCPConnection)
	} else {
		connection = NewTCPConnection()
		connection.Auth.RemoteIP = tcpPacket.DestinationAddress.String()
		connection.Auth.RemotePort = strconv.Itoa(int(tcpPacket.DestinationPort))
	}

	// Create TCP Option
	tcpOptions := d.createTCPAuthenticationOption([]byte{})

	// Create a token
	tcpData := d.createPacketToken(false, context.(*PUContext), &connection.Auth)

	// Track the connection
	connection.State = TCPSynSend
	d.appConnectionTracker.AddOrUpdate(tcpPacket.L4FlowHash(), connection)
	d.contextConnectionTracker.AddOrUpdate(string(connection.Auth.LocalContext), connection)
	d.sourcePortCache.AddOrUpdate(tcpPacket.L4FlowHash(), context)
	// Attach the tags to the packet. We use a trick to reduce the seq number from ISN so that when our component gets out of the way, the
	// sequence numbers between the TCP stacks automatically match
	tcpPacket.DecreaseTCPSeq(uint32(len(tcpData)-1) + (d.ackSize))
	if err := tcpPacket.TCPDataAttach(tcpOptions, tcpData); err != nil {
		return nil, err
	}

	tcpPacket.UpdateTCPChecksum()
	return nil, nil
}

func (d *datapathEnforcer) processApplicationSynAckPacket(tcpPacket *packet.Packet) (interface{}, error) {
	var context interface{}
	var err error

	if d.mode != constants.LocalContainer && tcpPacket.TCPFlags == packet.TCPSynAckMask {
		if context, err = d.destinationPortCache.Get(tcpPacket.L4ReverseFlowHash()); err != nil {
			return nil, err
		}
	} else {
		context, err = d.contextFromIP(true, tcpPacket.SourceAddress.String(), tcpPacket.Mark, strconv.Itoa(int(tcpPacket.DestinationPort)))
	}

	if err != nil {
		return nil, nil
	}

	// Create the reverse hash since we have cached based on the SYN and
	// Retrieve the connection context
	c, err := d.networkConnectionTracker.Get(tcpPacket.L4ReverseFlowHash())
	if err != nil {
		return nil, nil
	}

	connection := c.(*TCPConnection)

	// Process the packet if I am the right state. I should have either received a Syn packet or
	// I could have send a SynAck and this is a duplicate request since my response was lost.
	if connection.State == TCPSynReceived || connection.State == TCPSynAckSend {

		connection.State = TCPSynAckSend

		// Create TCP Option
		tcpOptions := d.createTCPAuthenticationOption([]byte{})

		// Create a token
		tcpData := d.createPacketToken(false, context.(*PUContext), &connection.Auth)

		// Attach the tags to the packet
		tcpPacket.DecreaseTCPSeq(uint32(len(tcpData) - 1))
		tcpPacket.DecreaseTCPAck(d.ackSize)
		if err := tcpPacket.TCPDataAttach(tcpOptions, tcpData); err != nil {
			return nil, err
		}

		tcpPacket.UpdateTCPChecksum()
		return nil, nil
	}

	return nil, fmt.Errorf("Received SynACK in wrong state ")
}

func (d *datapathEnforcer) processApplicationAckPacket(tcpPacket *packet.Packet) (interface{}, error) {

	// Find the container context
	context, cerr := d.contextFromIP(true, tcpPacket.SourceAddress.String(), tcpPacket.Mark, strconv.Itoa(int(tcpPacket.DestinationPort)))

	if cerr != nil {
		// Let these ACK packets through
		return nil, nil
	}

	// Get the connection state. We need the state of the two random numbers
	c, err := d.appConnectionTracker.Get(tcpPacket.L4FlowHash())
	if err != nil {
		// Untracked connection. Let it go through
		return nil, nil
	}

	connection := c.(*TCPConnection)

	// Only process in SynAckReceived state
	if connection.State == TCPSynAckReceived {
		// Create a new token that includes the source and destinatio nonse
		// These are both challenges signed by the secret key and random for every
		// connection minimizing the chances of a replay attack
		token := d.createPacketToken(true, context.(*PUContext), &connection.Auth)

		tcpOptions := d.createTCPAuthenticationOption([]byte{})

		if len(token) != int(d.ackSize) {
			return nil, fmt.Errorf("Protocol Error %d", len(token))
		}

		// Attach the tags to the packet
		tcpPacket.DecreaseTCPSeq(d.ackSize)
		if err := tcpPacket.TCPDataAttach(tcpOptions, token); err != nil {
			return nil, err
		}
		tcpPacket.UpdateTCPChecksum()

		connection.State = TCPAckSend

		return nil, nil
	}

	// Catch the first request packet
	if connection.State == TCPAckSend {
		//Delete the state at this point .. There is a small chance that both packets are lost
		// and the other side will send us SYNACK again .. TBD if we need to change this
		if err := d.contextConnectionTracker.Remove(string(connection.Auth.LocalContext)); err != nil {
			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Warn("Failed to clean up cache state")
		}
		d.sourcePortCache.Remove(tcpPacket.L4FlowHash())
		d.destinationPortCache.Remove(tcpPacket.L4FlowHash())
		if err := d.appConnectionTracker.Remove(tcpPacket.L4FlowHash()); err != nil {
			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Warn("Failed to clean up cache state")
		}
		return nil, nil
	}

	return nil, fmt.Errorf("Received application ACK packet in the wrong state! %v", connection.State)
}

func (d *datapathEnforcer) processApplicationTCPPacket(tcpPacket *packet.Packet) (interface{}, error) {

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

	// Decode the JWT token using the context key
	// We need to add here to key renewal option where we decode with keys N, N-1
	// TBD
	claims, err := d.parsePacketToken(&connection.Auth, tcpPacket.ReadTCPData())

	// If the token signature is not valid
	// We must drop the connection and we drop the Syn packet. The source will
	// retry but we have no state to maintain here.
	if err != nil || claims == nil {

		d.collector.CollectFlowEvent(&collector.FlowRecord{
			ContextID:       context.ID,
			SourceID:        "",
			DestinationID:   context.ManagementID,
			Tags:            context.Annotations,
			Action:          collector.FlowReject,
			Mode:            collector.InvalidToken,
			SourceIP:        tcpPacket.SourceAddress.String(),
			DestinationIP:   tcpPacket.DestinationAddress.String(),
			DestinationPort: tcpPacket.DestinationPort,
		})

		return nil, fmt.Errorf("Syn packet dropped because of invalid token %v %+v", err, claims)
	}

	txLabel, ok := claims.T.Get(TransmitterLabel)
	if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); !ok || err != nil {
		d.collector.CollectFlowEvent(&collector.FlowRecord{
			ContextID:       context.ID,
			SourceID:        txLabel,
			DestinationID:   context.ManagementID,
			Tags:            context.Annotations,
			Action:          collector.FlowReject,
			Mode:            collector.InvalidFormat,
			SourceIP:        tcpPacket.SourceAddress.String(),
			DestinationIP:   tcpPacket.DestinationAddress.String(),
			DestinationPort: tcpPacket.DestinationPort,
		})

		return nil, fmt.Errorf("TCP Authentication Option not found %v", err)
	}

	// Remove any of our data from the packet. No matter what we don't need the
	// metadata any more.
	tcpDataLen := uint32(tcpPacket.IPTotalLength - tcpPacket.TCPDataStartBytes())
	tcpPacket.IncreaseTCPSeq((tcpDataLen - 1) + (d.ackSize))

	if err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen); err != nil {
		d.collector.CollectFlowEvent(&collector.FlowRecord{
			ContextID:       context.ID,
			DestinationID:   context.ManagementID,
			SourceID:        txLabel,
			Tags:            context.Annotations,
			Action:          collector.FlowReject,
			Mode:            collector.InvalidFormat,
			SourceIP:        tcpPacket.SourceAddress.String(),
			DestinationIP:   tcpPacket.DestinationAddress.String(),
			DestinationPort: tcpPacket.DestinationPort,
		})

		return nil, fmt.Errorf("Syn packet dropped because of invalid format %v", err)
	}

	tcpPacket.DropDetachedBytes()
	tcpPacket.UpdateTCPChecksum()

	// Add the port as a label with an @ prefix. These labels are invalid otherwise
	// If all policies are restricted by port numbers this will allow port-specific policies
	claims.T.Add(PortNumberLabelString, strconv.Itoa(int(tcpPacket.DestinationPort)))

	// Validate against reject rules first - We always process reject with higher priority
	if index, _ := context.rejectRcvRules.Search(claims.T); index >= 0 {
		// Reject the connection
		d.collector.CollectFlowEvent(&collector.FlowRecord{
			ContextID:       context.ID,
			SourceID:        txLabel,
			DestinationID:   context.ManagementID,
			Tags:            context.Annotations,
			Action:          collector.FlowReject,
			Mode:            collector.PolicyDrop,
			SourceIP:        tcpPacket.SourceAddress.String(),
			DestinationIP:   tcpPacket.DestinationAddress.String(),
			DestinationPort: tcpPacket.DestinationPort,
		})

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
		d.destinationPortCache.AddOrUpdate(hash, context)

		// Accept the connection
		return action, nil
	}

	d.collector.CollectFlowEvent(&collector.FlowRecord{
		ContextID:       context.ID,
		SourceID:        txLabel,
		DestinationID:   context.ManagementID,
		Tags:            context.Annotations,
		Action:          collector.FlowReject,
		Mode:            collector.PolicyDrop,
		SourceIP:        tcpPacket.SourceAddress.String(),
		DestinationIP:   tcpPacket.DestinationAddress.String(),
		DestinationPort: tcpPacket.DestinationPort,
	})

	return nil, fmt.Errorf("No matched tags - reject %+v", claims.T)
}

func (d *datapathEnforcer) processNetworkSynAckPacket(context *PUContext, tcpPacket *packet.Packet) (interface{}, error) {

	// First we need to receover our state of the connection. If we don't have any state
	// we drop the packets and the connections
	// connection, err := d.appConnectionTracker.Get(tcpPacket.L4ReverseFlowHash())
	tcpData := tcpPacket.ReadTCPData()
	if len(tcpData) == 0 {
		d.collector.CollectFlowEvent(&collector.FlowRecord{
			ContextID:       context.ID,
			SourceID:        context.ManagementID,
			DestinationID:   "",
			Tags:            context.Annotations,
			Action:          collector.FlowReject,
			Mode:            collector.MissingToken,
			SourceIP:        tcpPacket.SourceAddress.String(),
			DestinationIP:   tcpPacket.DestinationAddress.String(),
			DestinationPort: tcpPacket.DestinationPort,
		})

		return nil, fmt.Errorf("SynAck packet dropped because of missing token")
	}

	// Validate the certificate and parse the token
	claims, cert := d.tokenEngine.Decode(false, tcpData, nil)
	if claims == nil {

		d.collector.CollectFlowEvent(&collector.FlowRecord{
			ContextID:       context.ID,
			SourceID:        context.ManagementID,
			DestinationID:   "",
			Tags:            context.Annotations,
			Action:          collector.FlowReject,
			Mode:            collector.MissingToken,
			SourceIP:        tcpPacket.SourceAddress.String(),
			DestinationIP:   tcpPacket.DestinationAddress.String(),
			DestinationPort: tcpPacket.DestinationPort,
		})

		return nil, fmt.Errorf("Synack  packet dropped because of bad claims %v", claims)
	}

	// We always a need a valid remote context ID
	remoteContextID, ok := claims.T.Get(TransmitterLabel)
	if !ok {
		return nil, fmt.Errorf("No remote context %v", claims.T)
	}

	c, err := d.contextConnectionTracker.Get(string(claims.RMT))
	if err != nil {
		d.contextConnectionTracker.DumpStore()
		return nil, fmt.Errorf("No connection found for %v", claims.RMT)
	}

	connection := c.(*TCPConnection)

	// Stash connection
	connection.Auth.RemotePublicKey = cert
	connection.Auth.RemoteContext = claims.LCL
	connection.Auth.RemoteContextID = remoteContextID
	tcpPacket.ConnectionMetadata = &connection.Auth

	if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); err != nil {

		d.collector.CollectFlowEvent(&collector.FlowRecord{
			ContextID:       context.ID,
			SourceID:        context.ManagementID,
			Tags:            context.Annotations,
			Action:          collector.FlowReject,
			Mode:            collector.InvalidFormat,
			DestinationID:   remoteContextID,
			SourceIP:        tcpPacket.SourceAddress.String(),
			DestinationIP:   tcpPacket.DestinationAddress.String(),
			DestinationPort: tcpPacket.DestinationPort,
		})

		return nil, fmt.Errorf("TCP Authentication Option not found")
	}

	// Remove any of our data
	tcpDataLen := uint32(tcpPacket.IPTotalLength - tcpPacket.TCPDataStartBytes())
	tcpPacket.IncreaseTCPSeq(tcpDataLen - 1)
	tcpPacket.IncreaseTCPAck(d.ackSize)

	if err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen); err != nil {

		d.collector.CollectFlowEvent(&collector.FlowRecord{
			ContextID:       context.ID,
			SourceID:        context.ManagementID,
			Tags:            context.Annotations,
			Action:          collector.FlowReject,
			Mode:            collector.InvalidFormat,
			DestinationID:   remoteContextID,
			SourceIP:        tcpPacket.SourceAddress.String(),
			DestinationIP:   tcpPacket.DestinationAddress.String(),
			DestinationPort: tcpPacket.DestinationPort,
		})

		return nil, fmt.Errorf("SynAck packet dropped because of invalid format")
	}

	tcpPacket.DropDetachedBytes()
	tcpPacket.UpdateTCPChecksum()

	// We can now verify the reverse policy. The system requires that policy
	// is matched in both directions. We have to make this optional as it can
	// become a very strong condition

	// First validate that there are no reject rules
	if index, _ := context.rejectTxtRules.Search(claims.T); d.mutualAuthorization && index >= 0 {
		d.collector.CollectFlowEvent(&collector.FlowRecord{
			ContextID:       context.ID,
			SourceID:        context.ManagementID,
			Tags:            context.Annotations,
			Action:          collector.FlowReject,
			Mode:            collector.PolicyDrop,
			DestinationID:   remoteContextID,
			SourceIP:        tcpPacket.SourceAddress.String(),
			DestinationIP:   tcpPacket.DestinationAddress.String(),
			DestinationPort: tcpPacket.DestinationPort,
		})

		return nil, fmt.Errorf("Dropping because of reject rule on transmitter")
	}

	if index, action := context.acceptTxtRules.Search(claims.T); !d.mutualAuthorization || index >= 0 {
		connection.State = TCPSynAckReceived
		return action, nil
	}

	d.collector.CollectFlowEvent(&collector.FlowRecord{
		ContextID:       context.ID,
		SourceID:        context.ManagementID,
		Tags:            context.Annotations,
		Action:          collector.FlowReject,
		Mode:            collector.PolicyDrop,
		DestinationID:   remoteContextID,
		SourceIP:        tcpPacket.SourceAddress.String(),
		DestinationIP:   tcpPacket.DestinationAddress.String(),
		DestinationPort: tcpPacket.DestinationPort,
	})

	return nil, fmt.Errorf("Dropping packet SYNACK at the network ")
}

func (d *datapathEnforcer) processNetworkAckPacket(context *PUContext, tcpPacket *packet.Packet) (interface{}, error) {

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

			d.collector.CollectFlowEvent(&collector.FlowRecord{
				ContextID:       context.ID,
				DestinationID:   context.ManagementID,
				Tags:            context.Annotations,
				Action:          collector.FlowReject,
				Mode:            collector.InvalidFormat,
				SourceID:        "",
				SourceIP:        tcpPacket.SourceAddress.String(),
				DestinationIP:   tcpPacket.DestinationAddress.String(),
				DestinationPort: tcpPacket.DestinationPort,
			})

			return nil, fmt.Errorf("TCP Authentication Option not found")
		}

		if _, err := d.parseAckToken(&connection.Auth, tcpPacket.ReadTCPData()); err != nil {

			d.collector.CollectFlowEvent(&collector.FlowRecord{
				ContextID:       context.ID,
				DestinationID:   context.ManagementID,
				Tags:            context.Annotations,
				Action:          collector.FlowReject,
				Mode:            collector.InvalidFormat,
				SourceID:        "",
				SourceIP:        tcpPacket.SourceAddress.String(),
				DestinationIP:   tcpPacket.DestinationAddress.String(),
				DestinationPort: tcpPacket.DestinationPort,
			})

			return nil, fmt.Errorf("Ack packet dropped because signature validation failed %v", err)
		}

		connection.State = TCPAckProcessed
		// Remove any of our data
		tcpPacket.IncreaseTCPSeq(d.ackSize)
		err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen)

		if err != nil {
			d.collector.CollectFlowEvent(&collector.FlowRecord{
				ContextID:       context.ID,
				DestinationID:   context.ManagementID,
				Tags:            context.Annotations,
				Action:          collector.FlowReject,
				Mode:            collector.InvalidFormat,
				SourceID:        "",
				SourceIP:        tcpPacket.SourceAddress.String(),
				DestinationIP:   tcpPacket.DestinationAddress.String(),
				DestinationPort: tcpPacket.DestinationPort,
			})
			return nil, fmt.Errorf("Ack packet dropped because of invalid format %v", err)
		}

		tcpPacket.DropDetachedBytes()

		tcpPacket.UpdateTCPChecksum()

		if err := d.networkConnectionTracker.Remove(hash); err != nil {
			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Warn("Failed to clean up cache state from network connection tracker")
		}

		// We accept the packet as a new flow
		d.collector.CollectFlowEvent(&collector.FlowRecord{
			ContextID:       context.ID,
			DestinationID:   context.ManagementID,
			Tags:            context.Annotations,
			Action:          collector.FlowAccept,
			Mode:            "NA",
			SourceID:        connection.Auth.RemoteContextID,
			SourceIP:        tcpPacket.SourceAddress.String(),
			DestinationIP:   tcpPacket.DestinationAddress.String(),
			DestinationPort: tcpPacket.DestinationPort,
		})

		// Accept the packet
		return nil, nil

	}

	// Everything else is dropped
	d.collector.CollectFlowEvent(&collector.FlowRecord{
		ContextID:       context.ID,
		DestinationID:   context.ManagementID,
		Tags:            context.Annotations,
		Action:          collector.FlowReject,
		Mode:            collector.InvalidState,
		SourceID:        connection.Auth.RemoteContextID,
		SourceIP:        tcpPacket.SourceAddress.String(),
		DestinationIP:   tcpPacket.DestinationAddress.String(),
		DestinationPort: tcpPacket.DestinationPort,
	})

	// Catch the first request packets
	if connection.State == TCPAckProcessed {
		// Safe to delete the state
		if err := d.networkConnectionTracker.Remove(hash); err != nil {
			log.WithFields(log.Fields{
				"package": "enforcer",
			}).Warn("Failed to clean up cache state from network connection tracker")
		}
		return nil, nil
	}

	return nil, fmt.Errorf("Ack packet dropped - no matching rules")
}

func (d *datapathEnforcer) processNetworkTCPPacket(tcpPacket *packet.Packet) (interface{}, error) {

	var err error
	var context interface{}

	if d.mode != constants.LocalContainer && tcpPacket.TCPFlags == packet.TCPSynAckMask {
		if context, err = d.sourcePortCache.Get(tcpPacket.L4ReverseFlowHash()); err != nil {
			return nil, nil
		}
	} else {
		// Lookup the policy rules for the packet - Return false if they don't exist
		context, err = d.contextFromIP(false, tcpPacket.DestinationAddress.String(), tcpPacket.Mark, strconv.Itoa(int(tcpPacket.DestinationPort)))
		if err != nil && d.service != nil && tcpPacket.TCPFlags&packet.TCPSynMask == 0 {
			return nil, nil
		}
	}

	if err != nil {
		return nil, fmt.Errorf("Context not found for container %s %v", tcpPacket.DestinationAddress.String(), d.puTracker)
	}

	// Update connection state in the internal state machine tracker
	switch tcpPacket.TCPFlags {

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
