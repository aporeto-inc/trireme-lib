package datapath

// Go libraries
import (
	"errors"
	"fmt"
	"strconv"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/cache"
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/connection"
	"github.com/aporeto-inc/trireme-lib/enforcer/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/pucontext"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/tokens"
	"github.com/aporeto-inc/trireme-lib/log"
	"github.com/aporeto-inc/trireme-lib/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// processNetworkPackets processes packets arriving from network and are destined to the application
func (d *Datapath) processNetworkTCPPackets(p *packet.Packet) (err error) {

	if log.Trace {
		zap.L().Debug("Processing network packet ",
			zap.String("flow", p.L4FlowHash()),
			zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
		)

		defer zap.L().Debug("Finished Processing network packet ",
			zap.String("flow", p.L4FlowHash()),
			zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
			zap.Error(err),
		)
	}

	var context *pucontext.PUContext
	var conn *connection.TCPConnection

	// Retrieve connection state of SynAck packets and
	// skip processing for SynAck packets that we don't have state
	switch p.TCPFlags & packet.TCPSynAckMask {
	case packet.TCPSynMask:
		context, conn, err = d.netSynRetrieveState(p)
		if err != nil {
			if log.Trace {
				zap.L().Debug("Packet rejected",
					zap.String("flow", p.L4FlowHash()),
					zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
					zap.Error(err),
				)
			}
			return err
		}

		if context.PUType == constants.TransientPU {
			//Drop Data and let packet through.
			//Don't create any state
			//The option should always be present since our rules looks for this option
			//context is destroyed here if we are a transient PU
			//Verdict get set to pass
			return nil
		}

	case packet.TCPSynAckMask:
		context, conn, err = d.netSynAckRetrieveState(p)
		if err != nil {
			if log.Trace {
				zap.L().Debug("SynAckPacket Ingored",
					zap.String("flow", p.L4FlowHash()),
					zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
				)
			}
			return nil
		}

	default:
		context, conn, err = d.netRetrieveState(p)
		if err != nil {
			if log.Trace {
				zap.L().Debug("Packet rejected",
					zap.String("flow", p.L4FlowHash()),
					zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
					zap.Error(err),
				)
			}
			return err
		}
	}

	conn.Lock()
	defer conn.Unlock()

	p.Print(packet.PacketStageIncoming)

	if d.service != nil {
		if !d.service.PreProcessTCPNetPacket(p, context, conn) {
			p.Print(packet.PacketFailureService)
			return errors.New("pre service processing failed for network packet")
		}
	}

	p.Print(packet.PacketStageAuth)

	// Match the tags of the packet against the policy rules - drop if the lookup fails
	action, claims, err := d.processNetworkTCPPacket(p, context, conn)
	if err != nil {
		p.Print(packet.PacketFailureAuth)
		if log.Trace {
			zap.L().Debug("Rejecting packet ",
				zap.String("flow", p.L4FlowHash()),
				zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
				zap.Error(err),
			)
		}
		return fmt.Errorf("packet processing failed for network packet: %s", err)
	}

	p.Print(packet.PacketStageService)

	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessTCPNetPacket(p, action, claims, context, conn) {
			p.Print(packet.PacketFailureService)
			return errors.New("post service processing failed for network packet")
		}

		if conn.ServiceConnection && conn.TimeOut > 0 {
			d.netReplyConnectionTracker.SetTimeOut(p.L4FlowHash(), conn.TimeOut) // nolint
		}

	}

	// Accept the packet
	p.UpdateTCPChecksum()
	p.Print(packet.PacketStageOutgoing)

	return nil
}

// processApplicationPackets processes packets arriving from an application and are destined to the network
func (d *Datapath) processApplicationTCPPackets(p *packet.Packet) (err error) {

	if log.Trace {
		zap.L().Debug("Processing application packet ",
			zap.String("flow", p.L4FlowHash()),
			zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
		)

		defer zap.L().Debug("Finished Processing application packet ",
			zap.String("flow", p.L4FlowHash()),
			zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
			zap.Error(err),
		)
	}

	var context *pucontext.PUContext
	var conn *connection.TCPConnection

	switch p.TCPFlags & packet.TCPSynAckMask {
	case packet.TCPSynMask:
		context, conn, err = d.appSynRetrieveState(p)
		if err != nil {
			if log.Trace {
				zap.L().Debug("Packet rejected",
					zap.String("flow", p.L4FlowHash()),
					zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
					zap.Error(err),
				)
			}
			return err
		}
	case packet.TCPSynAckMask:
		context, conn, err = d.appRetrieveState(p)
		if err != nil {
			if log.Trace {
				zap.L().Debug("SynAckPacket Ignored",
					zap.String("flow", p.L4FlowHash()),
					zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
				)
			}

			if p.Mark == strconv.Itoa(cgnetcls.Initialmarkval-1) {
				//SYN ACK came through the global rule.
				//This not from a process we are monitoring
				//let his packet through
				return nil
			}
			return err
		}
	default:
		context, conn, err = d.appRetrieveState(p)
		if err != nil {
			if log.Trace {
				zap.L().Debug("Packet rejected",
					zap.String("flow", p.L4FlowHash()),
					zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
					zap.Error(err),
				)
			}
			return err
		}
	}

	conn.Lock()
	defer conn.Unlock()

	p.Print(packet.PacketStageIncoming)

	if d.service != nil {
		// PreProcessServiceInterface
		if !d.service.PreProcessTCPAppPacket(p, context, conn) {
			p.Print(packet.PacketFailureService)
			return errors.New("pre service processing failed for application packet")
		}
	}

	p.Print(packet.PacketStageAuth)

	// Match the tags of the packet against the policy rules - drop if the lookup fails
	action, err := d.processApplicationTCPPacket(p, context, conn)
	if err != nil {
		if log.Trace {
			zap.L().Debug("Dropping packet  ",
				zap.String("flow", p.L4FlowHash()),
				zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
				zap.Error(err),
			)
		}
		p.Print(packet.PacketFailureAuth)
		return fmt.Errorf("processing failed for application packet: %s", err)
	}

	p.Print(packet.PacketStageService)

	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessTCPAppPacket(p, action, context, conn) {
			p.Print(packet.PacketFailureService)
			return errors.New("post service processing failed for application packet")
		}
	}

	// Accept the packet
	p.UpdateTCPChecksum()
	p.Print(packet.PacketStageOutgoing)
	return nil
}

// processApplicationTCPPacket processes a TCP packet and dispatches it to other methods based on the flags
func (d *Datapath) processApplicationTCPPacket(tcpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) (interface{}, error) {

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
func (d *Datapath) processApplicationSynPacket(tcpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) (interface{}, error) {

	// First check if the destination is in the external servicess approved cache
	// and if yes, allow the packet to go.
	context.Lock()
	if policy, err := context.ExternalIPCache.Get(tcpPacket.DestinationAddress.String() + ":" + strconv.Itoa(int(tcpPacket.DestinationPort))); err == nil {
		context.Unlock()
		d.appOrigConnectionTracker.AddOrUpdate(tcpPacket.L4FlowHash(), conn)
		d.sourcePortConnectionCache.AddOrUpdate(tcpPacket.SourcePortHash(packet.PacketTypeApplication), conn)
		return policy, nil
	}
	context.Unlock()

	// We are now processing as a Trireme packet that needs authorization headers
	// Create TCP Option
	tcpOptions := d.createTCPAuthenticationOption([]byte{})

	// Create a token
	context.Lock()
	tcpData, err := d.tokenAccessor.CreateSynPacketToken(context, &conn.Auth)
	context.Unlock()
	if err != nil {
		return nil, err
	}

	// Set the state indicating that we send out a Syn packet
	conn.SetState(connection.TCPSynSend)

	// Poplate the caches to track the connection
	hash := tcpPacket.L4FlowHash()
	d.appOrigConnectionTracker.AddOrUpdate(hash, conn)
	d.sourcePortConnectionCache.AddOrUpdate(tcpPacket.SourcePortHash(packet.PacketTypeApplication), conn)
	// Attach the tags to the packet and accept the packet
	return nil, tcpPacket.TCPDataAttach(tcpOptions, tcpData)

}

// processApplicationSynAckPacket processes an application SynAck packet
func (d *Datapath) processApplicationSynAckPacket(tcpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) (interface{}, error) {

	// If we are already in the connection.TCPData, it means that this is an external flow
	// At this point we can release the flow to the kernel by updating conntrack
	// We can also clean up the state since we are not going to see any more
	// packets from this connection.
	if conn.GetState() == connection.TCPData && !conn.ServiceConnection {
		if err := d.conntrackHdl.ConntrackTableUpdateMark(
			tcpPacket.DestinationAddress.String(),
			tcpPacket.SourceAddress.String(),
			tcpPacket.IPProto,
			tcpPacket.DestinationPort,
			tcpPacket.SourcePort,
			constants.DefaultConnMark,
		); err != nil {
			zap.L().Error("Failed to update conntrack entry for flow",
				zap.String("context", string(conn.Auth.LocalContext)),
				zap.String("app-conn", tcpPacket.L4ReverseFlowHash()),
				zap.String("state", fmt.Sprintf("%v", conn.GetState())),
			)
		}

		err1 := d.netOrigConnectionTracker.Remove(tcpPacket.L4ReverseFlowHash())
		err2 := d.appReplyConnectionTracker.Remove(tcpPacket.L4FlowHash())

		if err1 != nil || err2 != nil {
			zap.L().Debug("Failed to remove cache entries")
		}

		return nil, nil
	}

	// We now process packets that need authorization options
	// Process the packet at the right state. I should have either received a Syn packet or
	// I could have send a SynAck and this is a duplicate request since my response was lost.
	if conn.GetState() == connection.TCPSynReceived || conn.GetState() == connection.TCPSynAckSend {

		// Create TCP Option
		tcpOptions := d.createTCPAuthenticationOption([]byte{})

		// Create a token
		context.Lock()
		tcpData, err := d.tokenAccessor.CreateSynAckPacketToken(context, &conn.Auth)
		context.Unlock()

		if err != nil {
			return nil, err
		}

		// Set the state for future reference
		conn.SetState(connection.TCPSynAckSend)

		// Attach the tags to the packet
		return nil, tcpPacket.TCPDataAttach(tcpOptions, tcpData)
	}

	zap.L().Error("Invalid SynAck state while receiving SynAck packet",
		zap.String("context", string(conn.Auth.LocalContext)),
		zap.String("app-conn", tcpPacket.L4ReverseFlowHash()),
		zap.String("state", fmt.Sprintf("%v", conn.GetState())),
	)

	return nil, fmt.Errorf("received synack in wrong state: %v", conn.GetState())
}

// processApplicationAckPacket processes an application ack packet
func (d *Datapath) processApplicationAckPacket(tcpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) (interface{}, error) {

	// Only process the first Ack of a connection. This means that we have received
	// as SynAck packet and we can now process the ACK.
	if conn.GetState() == connection.TCPSynAckReceived && tcpPacket.IsEmptyTCPPayload() {

		// Create a new token that includes the source and destinatio nonse
		// These are both challenges signed by the secret key and random for every
		// connection minimizing the chances of a replay attack
		context.Lock()
		token, err := d.tokenAccessor.CreateAckPacketToken(context, &conn.Auth)
		context.Unlock()
		if err != nil {
			return nil, err
		}

		tcpOptions := d.createTCPAuthenticationOption([]byte{})

		// Since we adjust sequence numbers let's make sure we haven't made a mistake
		if len(token) != int(d.ackSize) {
			return nil, fmt.Errorf("protocol error: tokenlen=%d acksize=%d", len(token), int(d.ackSize))
		}

		// Attach the tags to the packet
		if err := tcpPacket.TCPDataAttach(tcpOptions, token); err != nil {
			return nil, err
		}

		conn.SetState(connection.TCPAckSend)

		// If its not a service connection, we release it to the kernel. Subsequent
		// packets after the first data packet, that might be already in the queue
		// will be transmitted through the kernel directly. Service connections are
		// delegated to the service module
		if !conn.ServiceConnection && tcpPacket.SourceAddress.String() != tcpPacket.DestinationAddress.String() {
			if err := d.conntrackHdl.ConntrackTableUpdateMark(
				tcpPacket.SourceAddress.String(),
				tcpPacket.DestinationAddress.String(),
				tcpPacket.IPProto,
				tcpPacket.SourcePort,
				tcpPacket.DestinationPort,
				constants.DefaultConnMark,
			); err != nil {
				zap.L().Error("Failed to update conntrack table for flow",
					zap.String("context", string(conn.Auth.LocalContext)),
					zap.String("app-conn", tcpPacket.L4ReverseFlowHash()),
					zap.String("state", fmt.Sprintf("%v", conn.GetState())),
				)
			}
		}

		return nil, nil
	}

	// If we are already in the connection.TCPData connection just forward the packet
	if conn.GetState() == connection.TCPData {
		return nil, nil
	}

	// Here we capture the first data packet after an ACK packet by modyfing the
	// state. We will not release the caches though to deal with re-transmissions.
	// We will let the caches expire.
	if conn.GetState() == connection.TCPAckSend {
		conn.SetState(connection.TCPData)
		return nil, nil
	}

	return nil, fmt.Errorf("received application ack packet in the wrong state: %v", conn.GetState())
}

// processNetworkTCPPacket processes a network TCP packet and dispatches it to different methods based on the flags
func (d *Datapath) processNetworkTCPPacket(tcpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) (action interface{}, claims *tokens.ConnectionClaims, err error) {

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
func (d *Datapath) processNetworkSynPacket(context *pucontext.PUContext, conn *connection.TCPConnection, tcpPacket *packet.Packet) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	context.Lock()
	defer context.Unlock()

	// Incoming packets that don't have our options are candidates to be processed
	// as external services.
	if err = tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {

		// If there is no auth option, attempt the ACLs
		plc, perr := context.NetworkACLS.GetMatchingAction(tcpPacket.SourceAddress.To4(), tcpPacket.DestinationPort)
		d.reportExternalServiceFlow(context, plc, false, tcpPacket)
		if perr != nil || plc.Action == policy.Reject {
			return nil, nil, fmt.Errorf("no auth or acls: outgoing connection dropped: %s", perr)
		}

		conn.SetState(connection.TCPData)
		d.netOrigConnectionTracker.AddOrUpdate(tcpPacket.L4FlowHash(), conn)
		d.appReplyConnectionTracker.AddOrUpdate(tcpPacket.L4ReverseFlowHash(), conn)

		return plc, nil, nil
	}

	// Packets that have authorization information go through the auth path
	// Decode the JWT token using the context key
	claims, err = d.tokenAccessor.ParsePacketToken(&conn.Auth, tcpPacket.ReadTCPData())

	// If the token signature is not valid or there are no claims
	// we must drop the connection and we drop the Syn packet. The source will
	// retry but we have no state to maintain here.
	if err != nil || claims == nil {
		d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID, context, collector.InvalidToken, nil)
		return nil, nil, fmt.Errorf("syn packet dropped because of invalid token: %s", err)
	}

	txLabel, ok := claims.T.Get(enforcerconstants.TransmitterLabel)
	if err := tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); !ok || err != nil {
		d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID, context, collector.InvalidFormat, nil)
		return nil, nil, fmt.Errorf("tcp authentication option not found: %s", err)
	}

	// Remove any of our data from the packet. No matter what we don't need the
	// metadata any more.
	if err := tcpPacket.TCPDataDetach(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
		d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID, context, collector.InvalidFormat, nil)
		return nil, nil, fmt.Errorf("syn packet dropped because of invalid format: %s", err)
	}

	tcpPacket.DropDetachedBytes()

	// Add the port as a label with an @ prefix. These labels are invalid otherwise
	// If all policies are restricted by port numbers this will allow port-specific policies
	claims.T.AppendKeyValue(enforcerconstants.PortNumberLabelString, strconv.Itoa(int(tcpPacket.DestinationPort)))

	// Validate against reject rules first - We always process reject with higher priority
	if index, plc := context.RejectRcvRules.Search(claims.T); index >= 0 {
		// Reject the connection
		d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID, context, collector.PolicyDrop, plc.(*policy.FlowPolicy))
		return nil, nil, fmt.Errorf("connection rejected because of policy: %+v", claims.T)
	}

	// Search the policy rules for a matching rule.
	if index, action := context.AcceptRcvRules.Search(claims.T); index >= 0 {

		hash := tcpPacket.L4FlowHash()
		// Update the connection state and store the Nonse send to us by the host.
		// We use the nonse in the subsequent packets to achieve randomization.
		conn.SetState(connection.TCPSynReceived)

		// conntrack
		d.netOrigConnectionTracker.AddOrUpdate(hash, conn)
		d.appReplyConnectionTracker.AddOrUpdate(tcpPacket.L4ReverseFlowHash(), conn)

		// Cache the action
		conn.FlowPolicy = action.(*policy.FlowPolicy)

		// Accept the connection
		return action, claims, nil
	}

	d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID, context, collector.PolicyDrop, nil)
	return nil, nil, fmt.Errorf("no matched tags: reject %+v", claims.T)
}

// processNetworkSynAckPacket processes a SynAck packet arriving from the network
func (d *Datapath) processNetworkSynAckPacket(context *pucontext.PUContext, conn *connection.TCPConnection, tcpPacket *packet.Packet) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	context.Lock()
	defer context.Unlock()

	// Packets with no authorization are processed as external services based on the ACLS
	if err = tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
		var plc *policy.FlowPolicy

		flowHash := tcpPacket.SourceAddress.String() + ":" + strconv.Itoa(int(tcpPacket.SourcePort))
		if plci, perr := context.ExternalIPCache.Get(flowHash); perr == nil {
			plc = plci.(*policy.FlowPolicy)
			d.releaseFlow(context, plc, tcpPacket)
			return plc, nil, nil
		}

		// Never seen this IP before, let's parse them.
		plc, err = context.ApplicationACLs.GetMatchingAction(tcpPacket.SourceAddress.To4(), tcpPacket.SourcePort)
		if err != nil || plc.Action&policy.Reject > 0 {
			d.reportReverseExternalServiceFlow(context, plc, true, tcpPacket)
			return nil, nil, fmt.Errorf("no auth or acls: drop synack packet and connection: %s: action=%d", err, plc.Action)
		}

		// Added to the cache if we can accept it
		if err = context.ExternalIPCache.Add(tcpPacket.SourceAddress.String()+":"+strconv.Itoa(int(tcpPacket.SourcePort)), plc); err != nil {
			d.releaseFlow(context, plc, tcpPacket)
			return nil, nil, fmt.Errorf("unable add ip to the cache: %s", err)
		}

		// Set the state to Data so the other state machines ignore subsequent packets
		conn.SetState(connection.TCPData)

		d.releaseFlow(context, plc, tcpPacket)

		return plc, nil, nil
	}

	// This is a corner condition. We are receiving a SynAck packet and we are in
	// a state that indicates that we have already processed one. This means that
	// our ack packet was lost. We need to revert conntrack in this case and get
	// back into the picture.
	if conn.GetState() != connection.TCPSynSend {

		// Revert the connmarks - dealing with retransmissions
		if cerr := d.conntrackHdl.ConntrackTableUpdateMark(
			tcpPacket.SourceAddress.String(),
			tcpPacket.DestinationAddress.String(),
			tcpPacket.IPProto,
			tcpPacket.SourcePort,
			tcpPacket.DestinationPort,
			0,
		); cerr != nil {
			zap.L().Error("Failed to update conntrack table for flow",
				zap.String("context", string(conn.Auth.LocalContext)),
				zap.String("app-conn", tcpPacket.L4ReverseFlowHash()),
				zap.String("state", fmt.Sprintf("%v", conn.GetState())),
			)
		}
	}

	// Now we can process the SynAck packet with its options
	tcpData := tcpPacket.ReadTCPData()
	if len(tcpData) == 0 {
		d.reportRejectedFlow(tcpPacket, nil, collector.DefaultEndPoint, context.ManagementID, context, collector.MissingToken, nil)
		return nil, nil, errors.New("synack packet dropped because of missing token")
	}

	claims, err = d.tokenAccessor.ParsePacketToken(&conn.Auth, tcpPacket.ReadTCPData())
	// // Validate the certificate and parse the token
	// claims, nonce, cert, err := d.tokenEngine.GetToken().Decode(false, tcpData, nil)
	if err != nil || claims == nil {
		d.reportRejectedFlow(tcpPacket, nil, collector.DefaultEndPoint, context.ManagementID, context, collector.MissingToken, nil)
		return nil, nil, fmt.Errorf("synack packet dropped because of bad claims: %s", err)
	}

	tcpPacket.ConnectionMetadata = &conn.Auth

	if err := tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
		d.reportRejectedFlow(tcpPacket, conn, context.ManagementID, conn.Auth.RemoteContextID, context, collector.InvalidFormat, nil)
		return nil, nil, fmt.Errorf("tcp authentication option not found: %s", err)
	}

	// Remove any of our data
	if err := tcpPacket.TCPDataDetach(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
		d.reportRejectedFlow(tcpPacket, conn, context.ManagementID, conn.Auth.RemoteContextID, context, collector.InvalidFormat, nil)
		return nil, nil, fmt.Errorf("synack packet dropped because of invalid format: %s", err)
	}

	tcpPacket.DropDetachedBytes()

	// We can now verify the reverse policy. The system requires that policy
	// is matched in both directions. We have to make this optional as it can
	// become a very strong condition
	if index, _ := context.RejectTxtRules.Search(claims.T); d.mutualAuthorization && index >= 0 {
		d.reportRejectedFlow(tcpPacket, conn, context.ManagementID, conn.Auth.RemoteContextID, context, collector.PolicyDrop, nil)
		return nil, nil, errors.New("dropping because of reject rule on transmitter")
	}

	if index, action := context.AcceptTxtRules.Search(claims.T); !d.mutualAuthorization || index >= 0 {
		conn.SetState(connection.TCPSynAckReceived)

		// conntrack
		d.netReplyConnectionTracker.AddOrUpdate(tcpPacket.L4FlowHash(), conn)
		return action, claims, nil
	}

	d.reportRejectedFlow(tcpPacket, conn, context.ManagementID, conn.Auth.RemoteContextID, context, collector.PolicyDrop, nil)
	return nil, nil, errors.New("dropping packet synack at the network")
}

// processNetworkAckPacket processes an Ack packet arriving from the network
func (d *Datapath) processNetworkAckPacket(context *pucontext.PUContext, conn *connection.TCPConnection, tcpPacket *packet.Packet) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	if conn.GetState() == connection.TCPData || conn.GetState() == connection.TCPAckSend {
		return nil, nil, nil
	}

	context.Lock()
	defer context.Unlock()

	hash := tcpPacket.L4FlowHash()

	// Validate that the source/destination nonse matches. The signature has validated both directions
	if conn.GetState() == connection.TCPSynAckSend || conn.GetState() == connection.TCPSynReceived {

		if err := tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
			d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID, context, collector.InvalidFormat, nil)
			return nil, nil, fmt.Errorf("tcp authentication option not found: %s", err)
		}

		if _, err := d.tokenAccessor.ParseAckToken(&conn.Auth, tcpPacket.ReadTCPData()); err != nil {
			d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID, context, collector.InvalidFormat, nil)
			return nil, nil, fmt.Errorf("ack packet dropped because signature validation failed: %s", err)
		}

		// Remove any of our data - adjust the sequence numbers
		if err := tcpPacket.TCPDataDetach(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
			d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID, context, collector.InvalidFormat, nil)
			return nil, nil, fmt.Errorf("ack packet dropped because of invalid format: %s", err)
		}

		tcpPacket.DropDetachedBytes()

		// We accept the packet as a new flow
		d.reportAcceptedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID, context, conn.FlowPolicy)

		conn.SetState(connection.TCPData)

		if !conn.ServiceConnection {
			if err := d.conntrackHdl.ConntrackTableUpdateMark(
				tcpPacket.SourceAddress.String(),
				tcpPacket.DestinationAddress.String(),
				tcpPacket.IPProto,
				tcpPacket.SourcePort,
				tcpPacket.DestinationPort,
				constants.DefaultConnMark,
			); err != nil {
				zap.L().Error("Failed to update conntrack table after ack packet")
			}
		}

		// Accept the packet
		return nil, nil, nil
	}

	if conn.ServiceConnection {
		return nil, nil, nil
	}

	// Everything else is dropped - ACK received in the Syn state without a SynAck
	d.reportRejectedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID, context, collector.InvalidState, nil)
	zap.L().Error("Invalid state reached",
		zap.String("state", fmt.Sprintf("%v", conn.GetState())),
		zap.String("context", context.ManagementID),
		zap.String("net-conn", hash),
	)

	return nil, nil, fmt.Errorf("ack packet dropped: invalid duplicate state: %+v", conn.GetState())
}

// createTCPAuthenticationOption creates the TCP authentication option -
func (d *Datapath) createTCPAuthenticationOption(token []byte) []byte {

	tokenLen := uint8(len(token))
	options := []byte{packet.TCPAuthenticationOption, enforcerconstants.TCPAuthenticationOptionBaseLen + tokenLen, 0, 0}

	if tokenLen != 0 {
		options = append(options, token...)
	}

	return options
}

// appSynRetrieveState retrieves state for the the application Syn packet.
// It creates a new connection by default
func (d *Datapath) appSynRetrieveState(p *packet.Packet) (*pucontext.PUContext, *connection.TCPConnection, error) {

	context, err := d.contextFromIP(true, p.SourceAddress.String(), p.Mark, strconv.Itoa(int(p.SourcePort)))
	if err != nil {
		return nil, nil, fmt.Errorf("no context in app processing: %s", err)
	}

	conn, err := d.appOrigConnectionTracker.GetReset(p.L4FlowHash(), 0)
	if err != nil {
		conn = connection.NewTCPConnection()

	}

	conn.(*connection.TCPConnection).Lock()
	conn.(*connection.TCPConnection).Context = context
	conn.(*connection.TCPConnection).Unlock()
	return context, conn.(*connection.TCPConnection), nil
}

func processSynAck(d *Datapath, p *packet.Packet, context *pucontext.PUContext) (*pucontext.PUContext, *connection.TCPConnection, error) {

	err := d.unknownSynConnectionTracker.Remove(p.L4ReverseFlowHash())
	if err != nil {
		// we are seeing a syn-ack for a syn we have not seen
		return nil, nil, fmt.Errorf("dropping synack for an unknown syn: %s", err)
	}

	d.puFromPort.AddOrUpdate(strconv.Itoa(int(p.SourcePort)), context)
	// Find the uid for which mark was asserted.
	uid, err := d.portSetInstance.GetUserMark(p.Mark)
	if err != nil {
		// Every outgoing packet has a mark. We should never come here
		return nil, nil, fmt.Errorf("did not find uid for the packet mark: %s", err)
	}

	// Add port to the cache and program the portset
	if _, err := d.portSetInstance.AddPortToUser(uid, strconv.Itoa(int(p.SourcePort))); err != nil {
		return nil, nil, fmt.Errorf("unable to update portset cache: %s", err)
	}
	// syn ack for which there is no corresponding syn context, so drop it.
	return nil, nil, errors.New("dropped synack for an unknown syn")
}

// appRetrieveState retrieves the state for the rest of the application packets. It
// returns an error if it cannot find the state
func (d *Datapath) appRetrieveState(p *packet.Packet) (*pucontext.PUContext, *connection.TCPConnection, error) {

	hash := p.L4FlowHash()
	conn, err := d.appReplyConnectionTracker.GetReset(hash, 0)
	if err != nil {
		conn, err = d.appOrigConnectionTracker.GetReset(hash, 0)
		if err != nil {
			if d.mode != constants.RemoteContainer && p.TCPFlags&packet.TCPSynAckMask == packet.TCPSynAckMask {
				// We see a syn ack for which we have not recorded a syn
				// Update the port for the context matching the mark this packet has comes with
				context, perr := d.contextFromIP(true, p.SourceAddress.String(), p.Mark, strconv.Itoa(int(p.SourcePort)))
				if perr == nil {
					// check cache and update portset cache accordingly.
					return processSynAck(d, p, context)
				}
			}

			return nil, nil, fmt.Errorf("app state not found: %s", err)
		}
		if uerr := updateTimer(d.appOrigConnectionTracker, hash, conn.(*connection.TCPConnection)); uerr != nil {
			return nil, nil, uerr
		}
	} else {
		if uerr := updateTimer(d.appReplyConnectionTracker, hash, conn.(*connection.TCPConnection)); uerr != nil {
			return nil, nil, uerr
		}
	}

	conn.(*connection.TCPConnection).Lock()
	defer conn.(*connection.TCPConnection).Unlock()
	context := conn.(*connection.TCPConnection).Context
	if context == nil {
		return nil, nil, errors.New("no context found")
	}

	return context.(*pucontext.PUContext), conn.(*connection.TCPConnection), nil
}

// netSynRetrieveState retrieves the state for the Syn packets on the network.
// Obviously if no state is found, it generates a new connection record.
func (d *Datapath) netSynRetrieveState(p *packet.Packet) (*pucontext.PUContext, *connection.TCPConnection, error) {

	context, err := d.contextFromIP(false, p.DestinationAddress.String(), p.Mark, strconv.Itoa(int(p.DestinationPort)))

	if err != nil {
		//This needs to hit only for local processes never for containers
		//Don't return an error create a dummy context and return it so we truncate the packet before we send it up
		if d.mode != constants.RemoteContainer {

			context = &pucontext.PUContext{
				PUType: constants.TransientPU,
			}
			//we will create the bare minimum needed to exercise our stack
			//We need this syn to look similar to what we will pass on the retry
			//so we setup enought for us to identify this request in the later stages

			// update the unknownSynConnectionTracker cache to keep track of
			// syn packet that has no context yet.
			if err = d.unknownSynConnectionTracker.Add(p.L4FlowHash(), nil); err != nil {
				return context, nil, fmt.Errorf("unable to keep track of syn packet: %s", err)
			}

			// Remove any of our data from the packet.
			if err = p.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
				return context, nil, nil
			}

			if err = p.TCPDataDetach(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
				return nil, nil, fmt.Errorf("syn packet dropped because of invalid format: %s", err)
			}

			p.DropDetachedBytes()

			p.UpdateTCPChecksum()

			return context, nil, nil
		}

		return nil, nil, errors.New("no context in net processing")
	}

	conn, err := d.netOrigConnectionTracker.GetReset(p.L4FlowHash(), 0)
	if err != nil {
		conn = connection.NewTCPConnection()
	}

	conn.(*connection.TCPConnection).Lock()
	conn.(*connection.TCPConnection).Context = context
	conn.(*connection.TCPConnection).Unlock()
	return context, conn.(*connection.TCPConnection), nil
}

// netSynAckRetrieveState retrieves the state for SynAck packets at the network
// It relies on the source port cache for that
func (d *Datapath) netSynAckRetrieveState(p *packet.Packet) (*pucontext.PUContext, *connection.TCPConnection, error) {

	conn, err := d.sourcePortConnectionCache.GetReset(p.SourcePortHash(packet.PacketTypeNetwork), 0)
	if err != nil {
		if log.Trace {
			zap.L().Debug("No connection for SynAck packet ",
				zap.String("flow", p.L4FlowHash()),
			)
		}
		return nil, nil, fmt.Errorf("no synack connection: %s", err)
	}

	conn.(*connection.TCPConnection).Lock()
	defer conn.(*connection.TCPConnection).Unlock()
	context := conn.(*connection.TCPConnection).Context
	if context == nil {
		return nil, nil, errors.New("no context found")
	}

	return context.(*pucontext.PUContext), conn.(*connection.TCPConnection), nil
}

// netRetrieveState retrieves the state of a network connection. Use the flow caches for that
func (d *Datapath) netRetrieveState(p *packet.Packet) (*pucontext.PUContext, *connection.TCPConnection, error) {
	hash := p.L4FlowHash()

	conn, err := d.netReplyConnectionTracker.GetReset(hash, 0)
	if err != nil {
		conn, err = d.netOrigConnectionTracker.GetReset(hash, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("net state not found: %s", err)
		}
		if uerr := updateTimer(d.netOrigConnectionTracker, hash, conn.(*connection.TCPConnection)); uerr != nil {
			return nil, nil, uerr
		}
	} else {
		if uerr := updateTimer(d.netReplyConnectionTracker, hash, conn.(*connection.TCPConnection)); uerr != nil {
			return nil, nil, uerr
		}
	}

	conn.(*connection.TCPConnection).Lock()
	defer conn.(*connection.TCPConnection).Unlock()
	context := conn.(*connection.TCPConnection).Context
	if context == nil {
		return nil, nil, errors.New("no context found")
	}

	return context.(*pucontext.PUContext), conn.(*connection.TCPConnection), nil

}

// updateTimer updates the timers for the service connections
func updateTimer(c cache.DataStore, hash string, conn *connection.TCPConnection) error {
	conn.Lock()
	defer conn.Unlock()

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
func (d *Datapath) contextFromIP(app bool, packetIP string, mark string, port string) (*pucontext.PUContext, error) {

	pu, err := d.puFromIP.Get(packetIP)
	if err == nil {
		return pu.(*pucontext.PUContext), nil
	}

	if err != nil && d.mode == constants.LocalContainer {
		return nil, fmt.Errorf("ip must be always populated to local containers: %s", err)
	}

	// Look for context based on the default IP
	defaultPU, err := d.puFromIP.Get(enforcerconstants.DefaultNetwork)
	if err == nil {
		return defaultPU.(*pucontext.PUContext), nil
	}

	if app {
		pu, err = d.puFromMark.Get(mark)
		if err != nil {
			return nil, fmt.Errorf("pu context cannot be found using mark %s: %s", mark, err)
		}
		return pu.(*pucontext.PUContext), nil
	}

	pu, err = d.puFromPort.Get(port)
	if err != nil {
		return nil, fmt.Errorf("pu context cannot be found using port %s: %s", port, err)
	}
	return pu.(*pucontext.PUContext), nil
}

// releaseFlow releases the flow and updates the conntrack table
func (d *Datapath) releaseFlow(context *pucontext.PUContext, plc *policy.FlowPolicy, tcpPacket *packet.Packet) {

	if err := d.appOrigConnectionTracker.Remove(tcpPacket.L4FlowHash()); err != nil {
		zap.L().Debug("Failed to clean cache appOrigConnectionTracker", zap.Error(err))
	}

	if err := d.sourcePortConnectionCache.Remove(tcpPacket.SourcePortHash(packet.PacketTypeApplication)); err != nil {
		zap.L().Debug("Failed to clean cache sourcePortConnectionCache", zap.Error(err))
	}

	if err := d.conntrackHdl.ConntrackTableUpdateMark(
		tcpPacket.DestinationAddress.String(),
		tcpPacket.SourceAddress.String(),
		tcpPacket.IPProto,
		tcpPacket.DestinationPort,
		tcpPacket.SourcePort,
		constants.DefaultConnMark,
	); err != nil {
		zap.L().Error("Failed to update conntrack table", zap.Error(err))
	}

	d.reportReverseExternalServiceFlow(context, plc, true, tcpPacket)
}
