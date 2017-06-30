package enforcer

// Go libraries
import (
	"bytes"
	"fmt"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
)

// processNetworkPackets processes packets arriving from network and are destined to the application
func (d *Datapath) processNetworkTCPPackets(p *packet.Packet) (err error) {

	zap.L().Debug("Processing network packet ",
		zap.String("flow", p.L4FlowHash()),
		zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
	)

	defer zap.L().Debug("Finished Processing network packet ",
		zap.String("flow", p.L4FlowHash()),
		zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
		zap.Error(err),
	)

	var context *PUContext
	var conn *TCPConnection

	// Retrieve connection state of SynAck packets and
	// skip processing for SynAck packets that we don't have state
	switch p.TCPFlags & packet.TCPSynAckMask {
	case packet.TCPSynMask:
		context, conn, err = d.netSynRetrieveState(p)
		if err != nil {
			zap.L().Debug("Packet rejected",
				zap.String("flow", p.L4FlowHash()),
				zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
				zap.Error(err),
			)
			return err
		}
	case packet.TCPSynAckMask:
		context, conn, err = d.netSynAckRetrieveState(p)
		if err != nil {
			zap.L().Debug("SynAckPacket Ingored",
				zap.String("flow", p.L4FlowHash()),
				zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
			)
			return nil
		}

	default:
		context, conn, err = d.netRetrieveState(p)
		if err != nil {
			zap.L().Debug("Packet rejected",
				zap.String("flow", p.L4FlowHash()),
				zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
				zap.Error(err),
			)
			return err
		}
	}

	conn.Lock()
	defer conn.Unlock()

	d.netTCP.IncomingPackets++
	p.Print(packet.PacketStageIncoming)

	if d.service != nil {
		if !d.service.PreProcessTCPNetPacket(p, context, conn) {
			d.netTCP.ServicePreDropPackets++
			p.Print(packet.PacketFailureService)
			return fmt.Errorf("Pre service processing failed for network packet")
		}
	}

	p.Print(packet.PacketStageAuth)

	// Match the tags of the packet against the policy rules - drop if the lookup fails
	action, claims, err := d.processNetworkTCPPacket(p, context, conn)
	if err != nil {
		d.netTCP.AuthDropPackets++
		p.Print(packet.PacketFailureAuth)
		zap.L().Debug("Rejecting packet ",
			zap.String("flow", p.L4FlowHash()),
			zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
			zap.Error(err),
		)
		return fmt.Errorf("Packet processing failed for network packet: %s", err.Error())
	}

	p.Print(packet.PacketStageService)

	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessTCPNetPacket(p, action, claims, context, conn) {
			d.netTCP.ServicePostDropPackets++
			p.Print(packet.PacketFailureService)
			return fmt.Errorf("PostPost service processing failed for network packet")
		}
	}

	// Accept the packet
	d.netTCP.OutgoingPackets++
	p.UpdateTCPChecksum()
	p.Print(packet.PacketStageOutgoing)

	return nil
}

// processApplicationPackets processes packets arriving from an application and are destined to the network
func (d *Datapath) processApplicationTCPPackets(p *packet.Packet) (err error) {

	zap.L().Debug("Processing application packet ",
		zap.String("flow", p.L4FlowHash()),
		zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
	)

	defer zap.L().Debug("Finished Processing application packet ",
		zap.String("flow", p.L4FlowHash()),
		zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
		zap.Error(err),
	)

	var context *PUContext
	var conn *TCPConnection

	switch p.TCPFlags & packet.TCPSynAckMask {
	case packet.TCPSynMask:
		context, conn, err = d.appSynRetrieveState(p)
		if err != nil {
			zap.L().Debug("Packet rejected",
				zap.String("flow", p.L4FlowHash()),
				zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
				zap.Error(err),
			)
			return err
		}
	case packet.TCPSynAckMask:
		context, conn, err = d.appRetrieveState(p)
		if err != nil {
			zap.L().Debug("SynAckPacket Ingored",
				zap.String("flow", p.L4FlowHash()),
				zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
			)
			return nil
		}
	default:
		context, conn, err = d.appRetrieveState(p)
		if err != nil {
			zap.L().Debug("Packet rejected",
				zap.String("flow", p.L4FlowHash()),
				zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
				zap.Error(err),
			)
			return err
		}
	}

	conn.Lock()
	defer conn.Unlock()

	d.appTCP.IncomingPackets++
	p.Print(packet.PacketStageIncoming)

	if d.service != nil {
		// PreProcessServiceInterface
		if !d.service.PreProcessTCPAppPacket(p, context, conn) {
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

	p.Print(packet.PacketStageService)

	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessTCPAppPacket(p, action, context, conn) {
			d.appTCP.ServicePostDropPackets++
			p.Print(packet.PacketFailureService)
			return fmt.Errorf("Post service processing failed for application packet")
		}
	}

	// Accept the packet
	d.appTCP.OutgoingPackets++
	p.UpdateTCPChecksum()
	p.Print(packet.PacketStageOutgoing)
	return nil
}

// processApplicationTCPPacket processes a TCP packet and dispatches it to other methods based on the flags
func (d *Datapath) processApplicationTCPPacket(tcpPacket *packet.Packet, context *PUContext, conn *TCPConnection) (interface{}, error) {

	if conn == nil {
		return nil, nil
	}

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
func (d *Datapath) processApplicationSynPacket(tcpPacket *packet.Packet, context *PUContext, conn *TCPConnection) (interface{}, error) {

	// Create TCP Option
	tcpOptions := d.createTCPAuthenticationOption([]byte{})

	// Create a token
	context.Lock()
	tcpData, err := d.createSynPacketToken(context, &conn.Auth)
	context.Unlock()
	if err != nil {
		return nil, err
	}
	// Track the connection/port cache
	hash := tcpPacket.L4FlowHash()
	conn.SetState(TCPSynSend)

	// conntrack
	d.appOrigConnectionTracker.AddOrUpdate(hash, conn)

	// Old trackers
	// d.appConnectionTracker.AddOrUpdate(hash, conn)
	// d.sourcePortCache.AddOrUpdate(tcpPacket.SourcePortHash(packet.PacketTypeApplication), context)
	d.sourcePortConnectionCache.AddOrUpdate(tcpPacket.SourcePortHash(packet.PacketTypeApplication), conn)

	// Attach the tags to the packet. We use a trick to reduce the seq number from ISN so that when our component gets out of the way, the
	// sequence numbers between the TCP stacks automatically match
	tcpPacket.DecreaseTCPSeq(uint32(len(tcpData)-1) + (d.ackSize))

	return nil, tcpPacket.TCPDataAttach(tcpOptions, tcpData)

}

// processApplicationSynAckPacket processes an application SynAck packet
func (d *Datapath) processApplicationSynAckPacket(tcpPacket *packet.Packet, context *PUContext, conn *TCPConnection) (interface{}, error) {

	// Process the packet at the right state. I should have either received a Syn packet or
	// I could have send a SynAck and this is a duplicate request since my response was lost.
	if conn.GetState() == TCPSynReceived || conn.GetState() == TCPSynAckSend {

		conn.SetState(TCPSynAckSend)

		// Create TCP Option
		tcpOptions := d.createTCPAuthenticationOption([]byte{})

		// Create a token
		context.Lock()
		tcpData, err := d.createSynAckPacketToken(context, &conn.Auth)
		context.Unlock()

		if err != nil {
			return nil, err
		}

		// Attach the tags to the packet
		tcpPacket.DecreaseTCPSeq(uint32(len(tcpData) - 1))
		tcpPacket.DecreaseTCPAck(d.ackSize)

		return nil, tcpPacket.TCPDataAttach(tcpOptions, tcpData)
	}

	zap.L().Error("Invalid SynAck state while receiving SynAck packet",
		zap.String("context", string(conn.Auth.LocalContext)),
		zap.String("app-conn", tcpPacket.L4ReverseFlowHash()),
		zap.String("state", fmt.Sprintf("%v", conn.GetState())),
	)

	return nil, fmt.Errorf("Received SynACK in wrong state %v", conn.GetState())
}

// processApplicationAckPacket processes an application ack packet
func (d *Datapath) processApplicationAckPacket(tcpPacket *packet.Packet, context *PUContext, conn *TCPConnection) (interface{}, error) {

	if conn.GetState() == TCPData {
		return nil, nil
	}

	// Only process in SynAckReceived state
	if conn.GetState() == TCPSynAckReceived || conn.GetState() == TCPSynSend {
		// Create a new token that includes the source and destinatio nonse
		// These are both challenges signed by the secret key and random for every
		// connection minimizing the chances of a replay attack
		context.Lock()
		token, err := d.createAckPacketToken(context, &conn.Auth)
		context.Unlock()
		if err != nil {
			return nil, err
		}

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

		conn.SetState(TCPAckSend)

		return nil, nil
	}

	// Catch the first request packet
	if conn.GetState() == TCPAckSend {

		// Once we have seen the end of the TCP SynAck sequence we have enough state
		// We can delete the source port cache to avoid any connection re-use issues
		// Flow caches will use a time out
		if err := d.sourcePortConnectionCache.Remove(tcpPacket.SourcePortHash(packet.PacketTypeApplication)); err != nil {
			zap.L().Warn("Failed to clean up cache state for connections",
				zap.String("src-port-hash", tcpPacket.SourcePortHash(packet.PacketTypeApplication)),
				zap.Error(err),
			)
		}

		conn.SetState(TCPData)
		return nil, nil
	}

	return nil, fmt.Errorf("Received application ACK packet in the wrong state! %v", conn.GetState())
}

// processNetworkTCPPacket processes a network TCP packet and dispatches it to different methods based on the flags
func (d *Datapath) processNetworkTCPPacket(tcpPacket *packet.Packet, context *PUContext, conn *TCPConnection) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	if conn == nil {
		return nil, nil, nil
	}

	// Update connection state in the internal state machine tracker
	switch tcpPacket.TCPFlags & packet.TCPSynAckMask {

	case packet.TCPSynMask:
		return d.processNetworkSynPacket(context, conn, tcpPacket)

	case packet.TCPAckMask:
		return d.processNetworkAckPacket(context, conn, tcpPacket)

	case packet.TCPSynAckMask:
		return d.processNetworkSynAckPacket(context, conn, tcpPacket)

	default: // Ignore any other packet
		return nil, nil, nil
	}
}

// processNetworkSynPacket processes a syn packet arriving from the network
func (d *Datapath) processNetworkSynPacket(context *PUContext, conn *TCPConnection, tcpPacket *packet.Packet) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	context.Lock()
	defer context.Unlock()
	// Decode the JWT token using the context key
	claims, err = d.parsePacketToken(&conn.Auth, tcpPacket.ReadTCPData())

	// If the token signature is not valid or there are no claims
	// we must drop the connection and we drop the Syn packet. The source will
	// retry but we have no state to maintain here.
	if err != nil || claims == nil {
		d.reportRejectedFlow(tcpPacket, conn, "", context.ManagementID, context, collector.InvalidToken)
		return nil, nil, fmt.Errorf("Syn packet dropped because of invalid token %v %+v", err, claims)
	}

	txLabel, ok := claims.T.Get(TransmitterLabel)
	if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); !ok || err != nil {
		d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID, context, collector.InvalidFormat)
		return nil, nil, fmt.Errorf("TCP Authentication Option not found %v", err)
	}

	// Remove any of our data from the packet. No matter what we don't need the
	// metadata any more.
	tcpDataLen := uint32(tcpPacket.IPTotalLength - tcpPacket.TCPDataStartBytes())
	tcpPacket.IncreaseTCPSeq((tcpDataLen - 1) + (d.ackSize))

	if err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen); err != nil {
		d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID, context, collector.InvalidFormat)
		return nil, nil, fmt.Errorf("Syn packet dropped because of invalid format %v", err)
	}

	tcpPacket.DropDetachedBytes()

	// Add the port as a label with an @ prefix. These labels are invalid otherwise
	// If all policies are restricted by port numbers this will allow port-specific policies
	claims.T.Add(PortNumberLabelString, strconv.Itoa(int(tcpPacket.DestinationPort)))

	// Validate against reject rules first - We always process reject with higher priority
	if index, _ := context.RejectRcvRules.Search(claims.T); index >= 0 {
		// Reject the connection
		d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID, context, collector.PolicyDrop)
		return nil, nil, fmt.Errorf("Connection rejected because of policy %+v", claims.T)
	}

	// Search the policy rules for a matching rule.
	if index, action := context.AcceptRcvRules.Search(claims.T); index >= 0 {

		hash := tcpPacket.L4FlowHash()
		// Update the connection state and store the Nonse send to us by the host.
		// We use the nonse in the subsequent packets to achieve randomization.
		conn.SetState(TCPSynReceived)

		// conntrack
		d.netOrigConnectionTracker.AddOrUpdate(hash, conn)
		d.appReplyConnectionTracker.AddOrUpdate(tcpPacket.L4ReverseFlowHash(), conn)

		// Accept the connection
		return action, claims, nil
	}

	d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID, context, collector.PolicyDrop)
	return nil, nil, fmt.Errorf("No matched tags - reject %+v", claims.T)
}

// processNetworkSynAckPacket processes a SynAck packet arriving from the network
func (d *Datapath) processNetworkSynAckPacket(context *PUContext, conn *TCPConnection, tcpPacket *packet.Packet) (action interface{}, claims *tokens.ConnectionClaims, err error) {
	context.Lock()
	defer context.Unlock()

	tcpData := tcpPacket.ReadTCPData()
	if len(tcpData) == 0 {
		d.reportRejectedFlow(tcpPacket, nil, "", context.ManagementID, context, collector.MissingToken)
		return nil, nil, fmt.Errorf("SynAck packet dropped because of missing token")
	}

	claims, err = d.parsePacketToken(&conn.Auth, tcpPacket.ReadTCPData())
	// // Validate the certificate and parse the token
	// claims, nonce, cert, err := d.tokenEngine.Decode(false, tcpData, nil)
	if err != nil || claims == nil {
		d.reportRejectedFlow(tcpPacket, nil, "", context.ManagementID, context, collector.MissingToken)
		return nil, nil, fmt.Errorf("Synack packet dropped because of bad claims %v", claims)
	}

	tcpPacket.ConnectionMetadata = &conn.Auth

	if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); err != nil {
		d.reportRejectedFlow(tcpPacket, conn, context.ManagementID, conn.Auth.RemoteContextID, context, collector.InvalidFormat)
		return nil, nil, fmt.Errorf("TCP Authentication Option not found")
	}

	// Remove any of our data
	tcpDataLen := uint32(tcpPacket.IPTotalLength - tcpPacket.TCPDataStartBytes())
	tcpPacket.IncreaseTCPSeq(tcpDataLen - 1)
	tcpPacket.IncreaseTCPAck(d.ackSize)

	if err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen); err != nil {
		d.reportRejectedFlow(tcpPacket, conn, context.ManagementID, conn.Auth.RemoteContextID, context, collector.InvalidFormat)
		return nil, nil, fmt.Errorf("SynAck packet dropped because of invalid format")
	}

	tcpPacket.DropDetachedBytes()

	// We can now verify the reverse policy. The system requires that policy
	// is matched in both directions. We have to make this optional as it can
	// become a very strong condition

	if index, _ := context.RejectTxtRules.Search(claims.T); d.mutualAuthorization && index >= 0 {
		d.reportRejectedFlow(tcpPacket, conn, context.ManagementID, conn.Auth.RemoteContextID, context, collector.PolicyDrop)
		return nil, nil, fmt.Errorf("Dropping because of reject rule on transmitter")
	}

	if index, action := context.AcceptTxtRules.Search(claims.T); !d.mutualAuthorization || index >= 0 {
		conn.SetState(TCPSynAckReceived)

		// conntrack
		d.netReplyConnectionTracker.AddOrUpdate(tcpPacket.L4FlowHash(), conn)
		return action, claims, nil
	}

	d.reportRejectedFlow(tcpPacket, conn, context.ManagementID, conn.Auth.RemoteContextID, context, collector.PolicyDrop)
	return nil, nil, fmt.Errorf("Dropping packet SYNACK at the network ")
}

// processNetworkAckPacket processes an Ack packet arriving from the network
func (d *Datapath) processNetworkAckPacket(context *PUContext, conn *TCPConnection, tcpPacket *packet.Packet) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	if conn.GetState() == TCPData || conn.GetState() == TCPAckSend {
		return nil, nil, nil
	}

	context.Lock()
	defer context.Unlock()

	hash := tcpPacket.L4FlowHash()

	// Validate that the source/destination nonse matches. The signature has validated both directions
	if conn.GetState() == TCPSynAckSend || conn.GetState() == TCPSynReceived {

		if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); err != nil {
			d.reportRejectedFlow(tcpPacket, conn, "", context.ManagementID, context, collector.InvalidFormat)
			return nil, nil, fmt.Errorf("TCP Authentication Option not found")
		}

		if _, err := d.parseAckToken(&conn.Auth, tcpPacket.ReadTCPData()); err != nil {
			d.reportRejectedFlow(tcpPacket, conn, "", context.ManagementID, context, collector.InvalidFormat)
			return nil, nil, fmt.Errorf("Ack packet dropped because signature validation failed %v", err)
		}

		// Remove any of our data - adjust the sequence numbers
		tcpPacket.IncreaseTCPSeq(d.ackSize)

		if err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen); err != nil {
			d.reportRejectedFlow(tcpPacket, conn, "", context.ManagementID, context, collector.InvalidFormat)
			return nil, nil, fmt.Errorf("Ack packet dropped because of invalid format %v", err)
		}

		tcpPacket.DropDetachedBytes()

		// We accept the packet as a new flow
		d.reportAcceptedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID, context)

		conn.SetState(TCPData)

		// Accept the packet
		return nil, nil, nil
	}

	if conn.ServiceConnection {
		return nil, nil, nil
	}

	// Everything else is dropped - ACK received in the Syn state without a SynAck
	d.reportRejectedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID, context, collector.InvalidState)
	zap.L().Error("Invalid state reached",
		zap.String("state", fmt.Sprintf("%v", conn.GetState())),
		zap.String("context", context.ManagementID),
		zap.String("net-conn", hash),
	)

	return nil, nil, fmt.Errorf("Ack packet dropped - Invalid State - Duplicate: %+v", conn.GetState())
}

// createacketToken creates the authentication token
func (d *Datapath) createAckPacketToken(context *PUContext, auth *AuthInfo) ([]byte, error) {

	claims := &tokens.ConnectionClaims{
		LCL: auth.LocalContext,
		RMT: auth.RemoteContext,
	}

	token, _, err := d.tokenEngine.CreateAndSign(true, claims)
	if err != nil {
		return []byte{}, err
	}

	return token, nil
}

// createSynPacketToken creates the authentication token
func (d *Datapath) createSynPacketToken(context *PUContext, auth *AuthInfo) (token []byte, err error) {

	if context.synExpiration.After(time.Now()) && len(context.synToken) > 0 {
		// Randomize the nonce and send it
		auth.LocalContext, err = d.tokenEngine.Randomize(context.synToken)
		if err == nil {
			return context.synToken, nil
		}
		// If there is an error, let's try to create a new one
	}

	claims := &tokens.ConnectionClaims{
		T: context.Identity,
	}

	if context.synToken, auth.LocalContext, err = d.tokenEngine.CreateAndSign(false, claims); err != nil {
		return []byte{}, nil
	}

	context.synExpiration = time.Now().Add(time.Millisecond * 500)

	return context.synToken, nil

}

// createSynAckPacketToken  creates the authentication token for SynAck packets
// We need to sign the received token. No caching possible here
func (d *Datapath) createSynAckPacketToken(context *PUContext, auth *AuthInfo) (token []byte, err error) {

	claims := &tokens.ConnectionClaims{
		T:   context.Identity,
		RMT: auth.RemoteContext,
	}

	if context.synToken, auth.LocalContext, err = d.tokenEngine.CreateAndSign(false, claims); err != nil {
		return []byte{}, nil
	}

	return context.synToken, nil

}

// parsePacketToken parses the packet token and populates the right state.
// Returns an error if the token cannot be parsed or the signature fails
func (d *Datapath) parsePacketToken(auth *AuthInfo, data []byte) (*tokens.ConnectionClaims, error) {

	// Validate the certificate and parse the token
	claims, nonce, cert, err := d.tokenEngine.Decode(false, data, auth.RemotePublicKey)
	if err != nil {
		return nil, err
	}

	// We always a need a valid remote context ID
	remoteContextID, ok := claims.T.Get(TransmitterLabel)
	if !ok {
		return nil, fmt.Errorf("No Transmitter Label ")
	}

	auth.RemotePublicKey = cert
	auth.RemoteContext = nonce
	auth.RemoteContextID = remoteContextID

	return claims, nil
}

// parseAckToken parses the tokens in Ack packets. They don't carry all the state context
// and it needs to be recovered
func (d *Datapath) parseAckToken(auth *AuthInfo, data []byte) (*tokens.ConnectionClaims, error) {

	// Validate the certificate and parse the token
	claims, _, _, err := d.tokenEngine.Decode(true, data, auth.RemotePublicKey)
	if err != nil {
		return nil, err
	}

	// Compare the incoming random context with the stored context
	matchLocal := bytes.Compare(claims.RMT, auth.LocalContext)
	matchRemote := bytes.Compare(claims.LCL, auth.RemoteContext)
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

// appSynRetrieveState retrieves state for the the application Syn packet.
// It creates a new connection by default
func (d *Datapath) appSynRetrieveState(p *packet.Packet) (*PUContext, *TCPConnection, error) {

	context, err := d.contextFromIP(true, p.SourceAddress.String(), p.Mark, strconv.Itoa(int(p.SourcePort)))
	if err != nil {
		return nil, nil, fmt.Errorf("No Context in App Processing")
	}

	conn, err := d.appOrigConnectionTracker.GetReset(p.L4FlowHash(), 0)
	if err != nil {
		conn = NewTCPConnection()

	}

	conn.(*TCPConnection).Lock()
	conn.(*TCPConnection).Context = context
	conn.(*TCPConnection).Unlock()
	return context, conn.(*TCPConnection), nil
}

// appRetrieveState retrieves the state for the rest of the application packets. It
// returns an error if it cannot find the state
func (d *Datapath) appRetrieveState(p *packet.Packet) (*PUContext, *TCPConnection, error) {
	hash := p.L4FlowHash()

	conn, err := d.appReplyConnectionTracker.GetReset(hash, 0)
	if err != nil {
		conn, err = d.appOrigConnectionTracker.GetReset(hash, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("App state not found")
		}
		if uerr := updateTimer(d.appOrigConnectionTracker, hash, conn.(*TCPConnection)); uerr != nil {
			return nil, nil, uerr
		}
	} else {
		if uerr := updateTimer(d.appReplyConnectionTracker, hash, conn.(*TCPConnection)); uerr != nil {
			return nil, nil, uerr
		}
	}

	conn.(*TCPConnection).Lock()
	defer conn.(*TCPConnection).Unlock()
	context := conn.(*TCPConnection).Context
	if context == nil {
		return nil, nil, fmt.Errorf("No context found")
	}

	return context, conn.(*TCPConnection), nil
}

// netSynRetrieveState retrieves the state for the Syn packets on the network.
// Obviously if no state is found, it generates a new connection record.
func (d *Datapath) netSynRetrieveState(p *packet.Packet) (*PUContext, *TCPConnection, error) {

	context, err := d.contextFromIP(false, p.DestinationAddress.String(), p.Mark, strconv.Itoa(int(p.DestinationPort)))
	if err != nil {
		return nil, nil, fmt.Errorf("No Context in App Processing")
	}

	conn, err := d.netOrigConnectionTracker.GetReset(p.L4FlowHash(), 0)
	if err != nil {
		conn = NewTCPConnection()
	}

	conn.(*TCPConnection).Lock()
	conn.(*TCPConnection).Context = context
	conn.(*TCPConnection).Unlock()

	return context, conn.(*TCPConnection), nil
}

// netSynAckRetrieveState retrieves the state for SynAck packets at the network
// It relies on the source port cache for that
func (d *Datapath) netSynAckRetrieveState(p *packet.Packet) (*PUContext, *TCPConnection, error) {

	conn, err := d.sourcePortConnectionCache.GetReset(p.SourcePortHash(packet.PacketTypeNetwork), 0)
	if err != nil {
		zap.L().Debug("No connection for SynAck packet ",
			zap.String("flow", p.L4FlowHash()),
		)
		return nil, nil, fmt.Errorf("No Synack Connection")
	}

	conn.(*TCPConnection).Lock()
	defer conn.(*TCPConnection).Unlock()
	context := conn.(*TCPConnection).Context
	if context == nil {
		return nil, nil, fmt.Errorf("No context found")
	}

	return context, conn.(*TCPConnection), nil
}

// netRetrieveState retrieves the state of a network connection. Use the flow caches for that
func (d *Datapath) netRetrieveState(p *packet.Packet) (*PUContext, *TCPConnection, error) {

	hash := p.L4FlowHash()

	conn, err := d.netReplyConnectionTracker.GetReset(hash, 0)
	if err != nil {
		conn, err = d.netOrigConnectionTracker.GetReset(hash, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("Net state not found")
		}
		if uerr := updateTimer(d.netOrigConnectionTracker, hash, conn.(*TCPConnection)); uerr != nil {
			return nil, nil, uerr
		}
	} else {
		if uerr := updateTimer(d.netReplyConnectionTracker, hash, conn.(*TCPConnection)); uerr != nil {
			return nil, nil, err
		}
	}

	conn.(*TCPConnection).Lock()
	defer conn.(*TCPConnection).Unlock()
	context := conn.(*TCPConnection).Context
	if context == nil {
		return nil, nil, fmt.Errorf("No context found")
	}

	return context, conn.(*TCPConnection), nil
}

// updateTimer updates the timers for the service connections
func updateTimer(c cache.DataStore, hash string, conn *TCPConnection) error {
	if conn.ServiceConnection && conn.TimeOut > 0 {
		return c.SetTimeOut(hash, conn.TimeOut)
	}
	return nil
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
