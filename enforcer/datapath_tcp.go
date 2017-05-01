package enforcer

// Go libraries
import (
	"bytes"
	"fmt"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/connection"
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
)

// TCPFlowState identifies the constants of the state of a TCP connectioncon
type TCPFlowState int

const (

	// TCPSynSend is the state where the Syn packets has been send, but no response has been received
	TCPSynSend TCPFlowState = iota

	// TCPSynReceived indicates that the syn packet has been received
	TCPSynReceived

	// TCPSynAckSend indicates that the SynAck packet has been send
	TCPSynAckSend

	// TCPSynAckReceived is the state where the SynAck has been received
	TCPSynAckReceived

	// TCPAckSend indicates that the ack packets has been send
	TCPAckSend

	// TCPAckProcessed is the state that the negotiation has been completed
	TCPAckProcessed
)

// processNetworkPackets processes packets arriving from network and are destined to the application
func (d *Datapath) processNetworkTCPPackets(p *packet.Packet) error {

	var context *PUContext
	var conn *connection.TCPConnection
	var err error

	zap.L().Debug("Processing network packet",
		zap.String("flow", p.L4FlowHash()),
		zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
	)

	// Retrieve connection state of SynAck packets and
	// skip processing for SynAck packets that we don't have state
	if p.TCPFlags == packet.TCPSynAckMask {
		context, conn, err = d.netRetrieveSynAckState(p)
	} else {
		context, conn, err = d.netRetrieveState(p)
	}

	if err != nil {
		zap.L().Debug("Packet rejected",
			zap.String("flow", p.L4FlowHash()),
			zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
			zap.Error(err),
		)
		return err
	}

	// if no connection for Ack packets accept them. We are done processing
	if conn == nil {
		zap.L().Debug("Ack packet - ignore connection state ",
			zap.String("flow", p.L4FlowHash()),
			zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
		)
		return nil
	}

	// Lock the connection context. No packets from the same connection
	// can be processed at the same time
	conn.Lock()
	defer conn.Unlock()

	d.netTCP.IncomingPackets++
	p.Print(packet.PacketStageIncoming)

	if d.service != nil {
		if !d.service.PreProcessTCPNetPacket(p) {
			d.netTCP.ServicePreDropPackets++
			p.Print(packet.PacketFailureService)
			return fmt.Errorf("Pre service processing failed for network packet")
		}
	}

	p.Print(packet.PacketStageAuth)

	// Match the tags of the packet against the policy rules - drop if the lookup fails
	action, err := d.processNetworkTCPPacket(p, context, conn)
	if err != nil {
		d.netTCP.AuthDropPackets++
		p.Print(packet.PacketFailureAuth)
		return fmt.Errorf("Packet processing failed for network packet: %s", err.Error())
	}

	p.Print(packet.PacketStageService)

	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessTCPNetPacket(p, action) {
			d.netTCP.ServicePostDropPackets++
			p.Print(packet.PacketFailureService)
			return fmt.Errorf("PostPost service processing failed for network packet")
		}
	}

	// Accept the packet
	d.netTCP.OutgoingPackets++
	p.Print(packet.PacketStageOutgoing)
	return nil
}

// processApplicationPackets processes packets arriving from an application and are destined to the network
func (d *Datapath) processApplicationTCPPackets(p *packet.Packet) error {

	zap.L().Debug("Processing application packet ",
		zap.String("flow", p.L4FlowHash()),
		zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
	)

	context, conn, err := d.appRetrieveState(p)
	if err != nil {
		// Ignoring SynAck packets since we get all of them
		if p.TCPFlags&packet.TCPSynAckMask == packet.TCPSynAckMask {
			zap.L().Debug("Ingroning SynAck packet ",
				zap.String("flow", p.L4FlowHash()),
			)
			return nil
		}

		// For other packets, if there is no connection, drop them
		zap.L().Debug("Dropping application packet - no context ",
			zap.String("flow", p.L4FlowHash()),
		)

		return fmt.Errorf("No context found in app processing")
	}

	// Only happens for TCP Ack packets after we are done processing - let them go
	if conn == nil {
		zap.L().Debug("Ignoring data ack packet ",
			zap.String("flow", p.L4FlowHash()),
			zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
		)
		return nil
	}

	// Lock the connection context to prevent concurrent packet processing
	conn.Lock()
	defer conn.Unlock()

	d.appTCP.IncomingPackets++
	p.Print(packet.PacketStageIncoming)

	if d.service != nil {
		// PreProcessServiceInterface
		if !d.service.PreProcessTCPAppPacket(p) {
			d.appTCP.ServicePreDropPackets++
			p.Print(packet.PacketFailureService)
			return fmt.Errorf("Pre service processing failed for application packet")
		}
	}

	p.Print(packet.PacketStageAuth)

	// Match the tags of the packet against the policy rules - drop if the lookup fails
	action, err := d.processApplicationTCPPacket(p, context, conn)
	if err != nil {
		zap.L().Debug("Dropping packet  ",
			zap.String("flow", p.L4FlowHash()),
			zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
			zap.Error(err),
		)
		d.appTCP.AuthDropPackets++
		p.Print(packet.PacketFailureAuth)
		return fmt.Errorf("Processing failed for application packet: %s", err.Error())
	}

	zap.L().Debug("Finished processing ",
		zap.String("flow", p.L4FlowHash()),
		zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
	)

	p.Print(packet.PacketStageService)

	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessTCPAppPacket(p, action) {
			d.appTCP.ServicePostDropPackets++
			p.Print(packet.PacketFailureService)
			return fmt.Errorf("Post service processing failed for application packet")
		}
	}

	// Accept the packet
	d.appTCP.OutgoingPackets++
	p.Print(packet.PacketStageOutgoing)
	return nil
}

// processApplicationTCPPacket processes a TCP packet and dispatches it to other methods based on the flags
func (d *Datapath) processApplicationTCPPacket(tcpPacket *packet.Packet, context *PUContext, conn *connection.TCPConnection) (interface{}, error) {

	// State machine based on the flags
	switch tcpPacket.TCPFlags & packet.TCPSynAckMask {
	case packet.TCPSynMask: //Processing SYN packet from Application
		action, err := d.processApplicationSynPacket(tcpPacket, context, conn)
		return action, err

	case packet.TCPAckMask:
		action, err := d.processApplicationAckPacket(tcpPacket, context, conn)
		return action, err

	case packet.TCPSynAckMask:
		action, err := d.processApplicationSynAckPacket(tcpPacket, context, conn)
		return action, err
	default:
		return nil, nil
	}
}

// processApplicationSynPacket processes a single Syn Packet
func (d *Datapath) processApplicationSynPacket(tcpPacket *packet.Packet, context *PUContext, conn *connection.TCPConnection) (interface{}, error) {

	// Create TCP Option
	tcpOptions := d.createTCPAuthenticationOption([]byte{})

	// Create a token
	context.Lock()
	tcpData := d.createPacketToken(false, context, &conn.Auth)
	context.Unlock()
	// Track the connection/port cache
	hash := tcpPacket.L4FlowHash()
	conn.SetState(connection.TCPSynSend)
	d.appConnectionTracker.AddOrUpdate(hash, conn)
	d.sourcePortCache.AddOrUpdate(tcpPacket.SourcePortHash(packet.PacketTypeApplication), context)
	d.sourcePortConnectionCache.AddOrUpdate(tcpPacket.SourcePortHash(packet.PacketTypeApplication), conn)

	// Attach the tags to the packet. We use a trick to reduce the seq number from ISN so that when our component gets out of the way, the
	// sequence numbers between the TCP stacks automatically match
	tcpPacket.DecreaseTCPSeq(uint32(len(tcpData)-1) + (d.ackSize))
	if err := tcpPacket.TCPDataAttach(tcpOptions, tcpData); err != nil {
		return nil, err
	}

	tcpPacket.UpdateTCPChecksum()
	return nil, nil
}

// processApplicationSynAckPacket processes an application SynAck packet
func (d *Datapath) processApplicationSynAckPacket(tcpPacket *packet.Packet, context *PUContext, conn *connection.TCPConnection) (interface{}, error) {

	// Process the packet at the right state. I should have either received a Syn packet or
	// I could have send a SynAck and this is a duplicate request since my response was lost.
	if conn.GetState() == connection.TCPSynReceived || conn.GetState() == connection.TCPSynAckSend {

		conn.SetState(connection.TCPSynAckSend)

		// Create TCP Option
		tcpOptions := d.createTCPAuthenticationOption([]byte{})

		// Create a token
		context.Lock()
		tcpData := d.createPacketToken(false, context, &conn.Auth)
		context.Unlock()

		// Attach the tags to the packet
		tcpPacket.DecreaseTCPSeq(uint32(len(tcpData) - 1))
		tcpPacket.DecreaseTCPAck(d.ackSize)
		if err := tcpPacket.TCPDataAttach(tcpOptions, tcpData); err != nil {
			return nil, err
		}

		tcpPacket.UpdateTCPChecksum()
		return nil, nil
	}

	zap.L().Error("Invalid SynAck state while receiving SynAck packet",
		zap.String("context", string(conn.Auth.LocalContext)),
		zap.String("app-conn", tcpPacket.L4ReverseFlowHash()),
		zap.String("state", fmt.Sprintf("%v", conn.GetState())),
	)

	return nil, fmt.Errorf("Received SynACK in wrong state %v", conn.GetState())
}

// processApplicationAckPacket processes an application ack packet
func (d *Datapath) processApplicationAckPacket(tcpPacket *packet.Packet, context *PUContext, conn *connection.TCPConnection) (interface{}, error) {

	// Only process in SynAckReceived state
	if conn.GetState() == connection.TCPSynAckReceived || conn.GetState() == connection.TCPSynSend {
		// Create a new token that includes the source and destinatio nonse
		// These are both challenges signed by the secret key and random for every
		// connection minimizing the chances of a replay attack
		context.Lock()
		token := d.createPacketToken(true, context, &conn.Auth)
		context.Unlock()

		tcpOptions := d.createTCPAuthenticationOption([]byte{})

		// Since we adjust sequence numbers let's make sure we haven't made a mistake
		if len(token) != int(d.ackSize) {
			return nil, fmt.Errorf("Protocol Error %d", len(token))
		}

		// Attach the tags to the packet
		tcpPacket.DecreaseTCPSeq(d.ackSize)
		if err := tcpPacket.TCPDataAttach(tcpOptions, token); err != nil {
			return nil, err
		}
		tcpPacket.UpdateTCPChecksum()

		conn.SetState(connection.TCPAckSend)

		return nil, nil
	}

	// Catch the first request packet
	if conn.GetState() == connection.TCPAckSend {
		//Delete the state at this point .. There is a small chance that both packets are lost
		// and the other side will send us SYNACK again .. TBD if we need to change this
		if err := d.appConnectionTracker.Remove(tcpPacket.L4FlowHash()); err != nil {
			zap.L().Warn("Failed to clean up cache state", zap.Error(err))
		}
		//Remove the sourceport cache entry here
		if err := d.sourcePortCache.Remove(tcpPacket.SourcePortHash(packet.PacketTypeApplication)); err != nil {
			zap.L().Warn("Failed to clean up cache state",
				zap.String("src-port-hash", tcpPacket.SourcePortHash(packet.PacketTypeApplication)),
				zap.Error(err),
			)
		}

		if err := d.sourcePortConnectionCache.Remove(tcpPacket.SourcePortHash(packet.PacketTypeApplication)); err != nil {
			zap.L().Warn("Failed to clean up cache state for connections",
				zap.String("src-port-hash", tcpPacket.SourcePortHash(packet.PacketTypeApplication)),
				zap.Error(err),
			)
		}

		return nil, nil
	}

	return nil, fmt.Errorf("Received application ACK packet in the wrong state! %v", conn.GetState())
}

// processNetworkTCPPacket processes a network TCP packet and dispatches it to different methods based on the flags
func (d *Datapath) processNetworkTCPPacket(tcpPacket *packet.Packet, context *PUContext, conn *connection.TCPConnection) (interface{}, error) {

	// Update connection state in the internal state machine tracker
	switch tcpPacket.TCPFlags {

	case packet.TCPSynMask & packet.TCPSynAckMask:
		return d.processNetworkSynPacket(context, conn, tcpPacket)

	case packet.TCPAckMask:
		return d.processNetworkAckPacket(context, conn, tcpPacket)

	case packet.TCPSynAckMask:
		return d.processNetworkSynAckPacket(context, conn, tcpPacket)

	default: // Ignore any other packet
		return nil, nil
	}
}

// processNetworkSynPacket processes a syn packet arriving from the network
func (d *Datapath) processNetworkSynPacket(context *PUContext, conn *connection.TCPConnection, tcpPacket *packet.Packet) (interface{}, error) {
	context.Lock()
	defer context.Unlock()
	// Decode the JWT token using the context key
	claims, err := d.parsePacketToken(&conn.Auth, tcpPacket.ReadTCPData())

	// If the token signature is not valid or there are no claims
	// we must drop the connection and we drop the Syn packet. The source will
	// retry but we have no state to maintain here.
	if err != nil || claims == nil {
		d.reportRejectedFlow(tcpPacket, conn, "", context.ManagementID, context, collector.InvalidToken)
		return nil, fmt.Errorf("Syn packet dropped because of invalid token %v %+v", err, claims)
	}

	txLabel, ok := claims.T.Get(TransmitterLabel)
	if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); !ok || err != nil {

		d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID, context, collector.InvalidFormat)
		return nil, fmt.Errorf("TCP Authentication Option not found %v", err)
	}

	// Remove any of our data from the packet. No matter what we don't need the
	// metadata any more.
	tcpDataLen := uint32(tcpPacket.IPTotalLength - tcpPacket.TCPDataStartBytes())
	tcpPacket.IncreaseTCPSeq((tcpDataLen - 1) + (d.ackSize))

	if err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen); err != nil {
		d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID, context, collector.InvalidFormat)
		return nil, fmt.Errorf("Syn packet dropped because of invalid format %v", err)
	}

	tcpPacket.DropDetachedBytes()
	tcpPacket.UpdateTCPChecksum()

	// Add the port as a label with an @ prefix. These labels are invalid otherwise
	// If all policies are restricted by port numbers this will allow port-specific policies
	claims.T.Add(PortNumberLabelString, strconv.Itoa(int(tcpPacket.DestinationPort)))

	// Validate against reject rules first - We always process reject with higher priority
	if index, _ := context.RejectRcvRules.Search(claims.T); index >= 0 {
		// Reject the connection
		d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID, context, collector.PolicyDrop)
		return nil, fmt.Errorf("Connection rejected because of policy %+v", claims.T)
	}

	// Search the policy rules for a matching rule.
	if index, action := context.AcceptRcvRules.Search(claims.T); index >= 0 {

		hash := tcpPacket.L4FlowHash()
		// Update the connection state and store the Nonse send to us by the host.
		// We use the nonse in the subsequent packets to achieve randomization.
		conn.SetState(connection.TCPSynReceived)
		// Note that if the connection exists already we will just end-up replicating it. No
		// harm here.
		d.networkConnectionTracker.AddOrUpdate(hash, conn)

		// Accept the connection
		return action, nil
	}

	d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID, context, collector.PolicyDrop)
	return nil, fmt.Errorf("No matched tags - reject %+v", claims.T)
}

// processNetworkSynAckPacket processes a SynAck packet arriving from the network
func (d *Datapath) processNetworkSynAckPacket(context *PUContext, conn *connection.TCPConnection, tcpPacket *packet.Packet) (interface{}, error) {
	context.Lock()
	defer context.Unlock()

	tcpData := tcpPacket.ReadTCPData()
	if len(tcpData) == 0 {
		d.reportRejectedFlow(tcpPacket, nil, "", context.ManagementID, context, collector.MissingToken)
		return nil, fmt.Errorf("SynAck packet dropped because of missing token")
	}

	// Validate the certificate and parse the token
	claims, cert := d.tokenEngine.Decode(false, tcpData, nil)
	if claims == nil {
		d.reportRejectedFlow(tcpPacket, nil, "", context.ManagementID, context, collector.MissingToken)
		return nil, fmt.Errorf("Synack packet dropped because of bad claims %v", claims)
	}

	// We always a need a valid remote context ID
	remoteContextID, ok := claims.T.Get(TransmitterLabel)
	if !ok {
		d.reportRejectedFlow(tcpPacket, nil, "", context.ManagementID, context, collector.InvalidContext)
		return nil, fmt.Errorf("No remote context %v", claims.T)
	}

	// Stash connection
	conn.Auth.RemotePublicKey = cert
	conn.Auth.RemoteContext = claims.LCL
	conn.Auth.RemoteContextID = remoteContextID
	tcpPacket.ConnectionMetadata = &conn.Auth

	if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); err != nil {
		d.reportRejectedFlow(tcpPacket, conn, context.ManagementID, remoteContextID, context, collector.InvalidFormat)
		return nil, fmt.Errorf("TCP Authentication Option not found")
	}

	// Remove any of our data
	tcpDataLen := uint32(tcpPacket.IPTotalLength - tcpPacket.TCPDataStartBytes())
	tcpPacket.IncreaseTCPSeq(tcpDataLen - 1)
	tcpPacket.IncreaseTCPAck(d.ackSize)

	if err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen); err != nil {
		d.reportRejectedFlow(tcpPacket, conn, context.ManagementID, remoteContextID, context, collector.InvalidFormat)
		return nil, fmt.Errorf("SynAck packet dropped because of invalid format")
	}

	tcpPacket.DropDetachedBytes()
	tcpPacket.UpdateTCPChecksum()

	// We can now verify the reverse policy. The system requires that policy
	// is matched in both directions. We have to make this optional as it can
	// become a very strong condition

	if index, _ := context.RejectTxtRules.Search(claims.T); d.mutualAuthorization && index >= 0 {
		d.reportRejectedFlow(tcpPacket, conn, context.ManagementID, remoteContextID, context, collector.PolicyDrop)
		return nil, fmt.Errorf("Dropping because of reject rule on transmitter")
	}

	if index, action := context.AcceptTxtRules.Search(claims.T); !d.mutualAuthorization || index >= 0 {
		conn.SetState(connection.TCPSynAckReceived)
		return action, nil
	}

	d.reportRejectedFlow(tcpPacket, conn, context.ManagementID, remoteContextID, context, collector.PolicyDrop)
	return nil, fmt.Errorf("Dropping packet SYNACK at the network ")
}

// processNetworkAckPacket processes an Ack packet arriving from the network
func (d *Datapath) processNetworkAckPacket(context *PUContext, conn *connection.TCPConnection, tcpPacket *packet.Packet) (interface{}, error) {
	context.Lock()
	defer context.Unlock()

	hash := tcpPacket.L4FlowHash()

	// Validate that the source/destination nonse matches. The signature has validated both directions
	if conn.GetState() == connection.TCPSynAckSend || conn.GetState() == connection.TCPSynReceived {

		if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); err != nil {
			d.reportRejectedFlow(tcpPacket, conn, "", context.ManagementID, context, collector.InvalidFormat)
			return nil, fmt.Errorf("TCP Authentication Option not found")
		}

		if _, err := d.parseAckToken(&conn.Auth, tcpPacket.ReadTCPData()); err != nil {
			d.reportRejectedFlow(tcpPacket, conn, "", context.ManagementID, context, collector.InvalidFormat)
			return nil, fmt.Errorf("Ack packet dropped because signature validation failed %v", err)
		}

		// Remove any of our data - adjust the sequence numbers
		tcpPacket.IncreaseTCPSeq(d.ackSize)

		if err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen); err != nil {
			d.reportRejectedFlow(tcpPacket, conn, "", context.ManagementID, context, collector.InvalidFormat)
			return nil, fmt.Errorf("Ack packet dropped because of invalid format %v", err)
		}

		tcpPacket.DropDetachedBytes()

		tcpPacket.UpdateTCPChecksum()

		// We accept the packet as a new flow
		d.reportAcceptedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID, context)

		// We are done - clean state and get out of the way
		if err := d.networkConnectionTracker.Remove(hash); err != nil {
			zap.L().Warn("Failed to clean up cache state from network connection tracker", zap.Error(err))
		}

		// Accept the packet
		return nil, nil
	}

	// Everything else is dropped - ACK received in the Syn state without a SynAck
	d.reportRejectedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID, context, collector.InvalidState)
	zap.L().Error("Invalid state reached",
		zap.String("state", fmt.Sprintf("%v", conn.GetState())),
		zap.String("context", context.ManagementID),
		zap.String("net-conn", hash),
	)

	return nil, fmt.Errorf("Ack packet dropped - Invalid State: %v", conn.GetState())
}

// createPacketToken creates the authentication token
func (d *Datapath) createPacketToken(ackToken bool, context *PUContext, auth *connection.AuthInfo) []byte {

	if !ackToken && context.synExpiration.After(time.Now()) && len(context.synToken) > 0 {
		return context.synToken
	}

	claims := &tokens.ConnectionClaims{
		LCL: auth.LocalContext,
		RMT: auth.RemoteContext,
	}

	if !ackToken {
		claims.T = context.Identity
	}

	context.synToken = d.tokenEngine.CreateAndSign(ackToken, claims)
	context.synExpiration = time.Now().Add(time.Millisecond * 500)

	return context.synToken

}

// parsePacketToken parses the packet token and populates the right state.
// Returns an error if the token cannot be parsed or the signature fails
func (d *Datapath) parsePacketToken(auth *connection.AuthInfo, data []byte) (*tokens.ConnectionClaims, error) {

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

// parseAckToken parses the tokens in Ack packets. They don't carry all the state context
// and it needs to be recovered
func (d *Datapath) parseAckToken(connection *connection.AuthInfo, data []byte) (*tokens.ConnectionClaims, error) {

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

// createTCPAuthenticationOption creates the TCP authentication option -
func (d *Datapath) createTCPAuthenticationOption(token []byte) []byte {

	tokenLen := uint8(len(token))
	options := []byte{packet.TCPAuthenticationOption, TCPAuthenticationOptionBaseLen + tokenLen, 0, 0}

	if tokenLen != 0 {
		options = append(options, token...)
	}

	return options
}

// appRetrieveState retrieves the state information for packets arriving from applications
func (d *Datapath) appRetrieveState(tcpPacket *packet.Packet) (*PUContext, *connection.TCPConnection, error) {

	var contextIP, contextPort string
	var mode bool

	// Find  the policy context based on IP information
	if tcpPacket.TCPFlags&packet.TCPSynAckMask == packet.TCPSynAckMask {
		contextIP = tcpPacket.DestinationAddress.String()
		contextPort = strconv.Itoa(int(tcpPacket.SourcePort))
		mode = false
	} else {
		contextIP = tcpPacket.SourceAddress.String()
		contextPort = strconv.Itoa(int(tcpPacket.DestinationPort))
		mode = true
	}

	context, cerr := d.contextFromIP(mode, contextIP, tcpPacket.Mark, contextPort)
	if cerr != nil {
		zap.L().Debug("No context found",
			zap.String("ip", contextIP),
			zap.String("mark", tcpPacket.Mark),
			zap.String("port", contextPort),
			zap.Error(cerr),
		)
		return nil, nil, fmt.Errorf("No Context in App Processing")
	}

	// Find the connection state
	switch tcpPacket.TCPFlags & packet.TCPSynAckMask {
	case packet.TCPSynMask: //Processing SYN packet from Application
		hash := tcpPacket.L4FlowHash()
		conn, err := d.appConnectionTracker.Get(hash)
		if err != nil {
			conn = connection.NewTCPConnection(false)
		}
		conn.(*connection.TCPConnection).SetPacketInfo(hash, packet.TCPFlagsToStr(tcpPacket.TCPFlags))
		return context, conn.(*connection.TCPConnection), nil

	case packet.TCPAckMask:
		hash := tcpPacket.L4FlowHash()
		conn, err := d.appConnectionTracker.Get(hash)
		if err != nil {
			return context, nil, nil
		}
		conn.(*connection.TCPConnection).SetPacketInfo(hash, packet.TCPFlagsToStr(tcpPacket.TCPFlags))
		return context, conn.(*connection.TCPConnection), nil

	case packet.TCPSynAckMask:
		hash := tcpPacket.L4ReverseFlowHash()
		conn, err := d.networkConnectionTracker.Get(hash)
		if err != nil {
			return context, nil, err
		}
		conn.(*connection.TCPConnection).SetPacketInfo(hash, packet.TCPFlagsToStr(tcpPacket.TCPFlags))
		return context, conn.(*connection.TCPConnection), nil
	}

	return nil, nil, nil
}

// netRetrieveState retrieves the state information for Syn and Ack packets.
// There is special handling for SynAck packets
func (d *Datapath) netRetrieveState(p *packet.Packet) (*PUContext, *connection.TCPConnection, error) {

	cachedContext, cerr := d.contextFromIP(false, p.DestinationAddress.String(), p.Mark, strconv.Itoa(int(p.DestinationPort)))
	if cerr != nil {
		zap.L().Debug("No context for packet - drop ",
			zap.String("flow", p.L4FlowHash()),
			zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
			zap.Error(cerr),
		)
		return nil, nil, fmt.Errorf("No context for packet")
	}

	// Find the connection state
	switch p.TCPFlags & packet.TCPSynAckMask {
	case packet.TCPSynMask: //Processing SYN packet from Application
		hash := p.L4FlowHash()
		conn, err := d.networkConnectionTracker.Get(hash)
		if err != nil {
			conn = connection.NewTCPConnection(true)
		}
		conn.(*connection.TCPConnection).SetPacketInfo(hash, packet.TCPFlagsToStr(p.TCPFlags))
		return cachedContext, conn.(*connection.TCPConnection), nil

	case packet.TCPAckMask:
		hash := p.L4FlowHash()
		conn, err := d.networkConnectionTracker.Get(hash)
		if err != nil {
			return nil, nil, nil
		}
		conn.(*connection.TCPConnection).SetPacketInfo(hash, packet.TCPFlagsToStr(p.TCPFlags))
		return cachedContext, conn.(*connection.TCPConnection), nil
	}
	return nil, nil, nil
}

// netRetrieveSynAckState retrieves context and connection state for SynAck
// packets. This is done using flow caches even for policy context
// Dealing with all variations of NAT here since we want to maintain support
// for mixed environments of Linux processes and containers
func (d *Datapath) netRetrieveSynAckState(p *packet.Packet) (*PUContext, *connection.TCPConnection, error) {
	cachedContext, err := d.sourcePortCache.Get(p.SourcePortHash(packet.PacketTypeNetwork))
	if err != nil {
		zap.L().Debug("Ingroning SynAck packet ",
			zap.String("flow", p.L4FlowHash()),
		)
		return nil, nil, nil
	}

	cachedConn, err := d.sourcePortConnectionCache.Get(p.SourcePortHash(packet.PacketTypeNetwork))
	if err != nil {
		zap.L().Debug("No connection for SynAck packet ",
			zap.String("flow", p.L4FlowHash()),
		)
		return nil, nil, fmt.Errorf("No Synack Connection")
	}

	return cachedContext.(*PUContext), cachedConn.(*connection.TCPConnection), nil
}

// contextFromIP returns the PU context from the default IP if remote. Otherwise
// it returns the context from the port or mark values of the packet. Synack
// packets are again special and the flow is reversed. If a container doesn't supply
// its IP information, we use the default IP. This will only work with remotes
// and Linux processes.
func (d *Datapath) contextFromIP(app bool, packetIP string, mark string, port string) (*PUContext, error) {

	pu, err := d.puFromIP.Get(packetIP)
	if err == nil {
		return pu.(*PUContext), nil
	}

	if err != nil && d.mode == constants.LocalContainer {
		return nil, fmt.Errorf("IP must be always populated to local containers")
	}

	// Look for context based on the default IP
	defaultPU, err := d.puFromIP.Get(DefaultNetwork)
	if err == nil {
		return defaultPU.(*PUContext), nil
	}

	if app {
		pu, err = d.puFromMark.Get(mark)
		if err != nil {
			return nil, fmt.Errorf("PU context cannot be found using mark %v ", mark)
		}
		return pu.(*PUContext), nil
	}

	pu, err = d.puFromPort.Get(port)
	if err != nil {
		return nil, fmt.Errorf("PU Context cannot be found using port key %v ", port)
	}
	return pu.(*PUContext), nil
}
