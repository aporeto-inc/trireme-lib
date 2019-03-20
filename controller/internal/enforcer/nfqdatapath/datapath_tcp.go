package nfqdatapath

// Go libraries
import (
	"fmt"
	"strconv"

	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	enforcerconstants "go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

var errInvalidNetState = errors.New("Invalid net state")
var errNonPUTraffic = errors.New("Traffic belongs to a PU we are not monitoring")
var errNetSynNotSeen = errors.New("Network Syn packet was not seen")
var errNoConnFound = errors.New("no context or connection found")
var errRejectPacket = errors.New("Reject the packet as per policy")
var errTCPAuthNotFound = errors.New("TCP authentication option not found")
var errSigValidFailed = errors.New("Ack packet dropped because signature validation failed")
var errInvalidFormat = errors.New("Ack packet dropped because of invalid format")
var errInvalidConnState = errors.New("Invalid connection state")

// processNetworkPackets processes packets arriving from network and are destined to the application
func (d *Datapath) processNetworkTCPPackets(p *packet.Packet) (conn *connection.TCPConnection, err error) {
	if d.packetLogs {
		zap.L().Debug("Processing network packet ",
			zap.String("flow", p.L4FlowHash()),
			zap.String("Flags", packet.TCPFlagsToStr(p.GetTCPFlags())),
		)

		defer zap.L().Debug("Finished Processing network packet ",
			zap.String("flow", p.L4FlowHash()),
			zap.String("Flags", packet.TCPFlagsToStr(p.GetTCPFlags())),
			zap.Error(err),
		)
	}

	//var conn *connection.TCPConnection

	// Retrieve connection state of SynAck packets and
	// skip processing for SynAck packets that we don't have state
	switch p.GetTCPFlags() & packet.TCPSynAckMask {
	case packet.TCPSynMask:
		conn, err = d.netSynRetrieveState(p)

		if err != nil {
			switch err {
			// Non PU Traffic let it through
			case errNonPUTraffic:
				return conn, nil
			default:
				if d.packetLogs {
					zap.L().Debug("Packet rejected",
						zap.String("flow", p.L4FlowHash()),
						zap.String("Flags", packet.TCPFlagsToStr(p.GetTCPFlags())),
						zap.Error(err),
					)
				}
				return conn, err
			}
		}

	case packet.TCPSynAckMask:
		conn, err = d.netSynAckRetrieveState(p)
		if err != nil {
			// This packet belongs to the client process that is not being enforcerd.
			// At this point, we can release this flow to kernel as we are not interested in
			// enforcing policy for the flow.
			d.releaseUnmonitoredFlow(p)
			return conn, nil
		}

	default:
		conn, err = d.netRetrieveState(p)
		if err != nil {
			if d.packetLogs {
				zap.L().Debug("Packet rejected",
					zap.String("flow", p.L4FlowHash()),
					zap.String("Flags", packet.TCPFlagsToStr(p.GetTCPFlags())),
					zap.Error(err),
				)
			}
			return conn, err
		}
	}

	conn.Lock()
	defer conn.Unlock()

	p.Print(packet.PacketStageIncoming)

	if d.service != nil {
		if !d.service.PreProcessTCPNetPacket(p, conn.Context, conn) {
			p.Print(packet.PacketFailureService)
			return conn, errors.New("pre service processing failed for network packet")
		}
	}

	p.Print(packet.PacketStageAuth)

	// Match the tags of the packet against the policy rules - drop if the lookup fails
	action, claims, err := d.processNetworkTCPPacket(p, conn.Context, conn)
	if err != nil {
		p.Print(packet.PacketFailureAuth)
		if d.packetLogs {
			zap.L().Debug("Rejecting packet ",
				zap.String("flow", p.L4FlowHash()),
				zap.String("Flags", packet.TCPFlagsToStr(p.GetTCPFlags())),
				zap.Error(err),
			)
		}
		return conn, fmt.Errorf("packet processing failed for network packet: %s", err)
	}

	p.Print(packet.PacketStageService)

	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessTCPNetPacket(p, action, claims, conn.Context, conn) {
			p.Print(packet.PacketFailureService)
			return conn, errors.New("post service processing failed for network packet")
		}

		if conn.ServiceConnection && conn.TimeOut > 0 {
			d.netReplyConnectionTracker.SetTimeOut(p.L4FlowHash(), conn.TimeOut) // nolint
		}

	}

	// Accept the packet
	p.UpdateTCPChecksum()
	p.Print(packet.PacketStageOutgoing)

	return conn, nil
}

// processApplicationPackets processes packets arriving from an application and are destined to the network
func (d *Datapath) processApplicationTCPPackets(p *packet.Packet) (conn *connection.TCPConnection, err error) {
	if d.packetLogs {
		zap.L().Debug("Processing application packet ",
			zap.String("flow", p.L4FlowHash()),
			zap.String("Flags", packet.TCPFlagsToStr(p.GetTCPFlags())),
		)

		defer zap.L().Debug("Finished Processing application packet ",
			zap.String("flow", p.L4FlowHash()),
			zap.String("Flags", packet.TCPFlagsToStr(p.GetTCPFlags())),
			zap.Error(err),
		)
	}

	switch p.GetTCPFlags() & packet.TCPSynAckMask {
	case packet.TCPSynMask:
		conn, err = d.appSynRetrieveState(p)
		if err != nil {
			if d.packetLogs {
				zap.L().Debug("Packet rejected",
					zap.String("flow", p.L4FlowHash()),
					zap.String("Flags", packet.TCPFlagsToStr(p.GetTCPFlags())),
					zap.Error(err),
				)
			}
			return conn, err
		}
	case packet.TCPSynAckMask:
		conn, err = d.appSynAckRetrieveState(p)
		if err != nil {
			if d.packetLogs {
				zap.L().Debug("SynAckPacket Ignored",
					zap.String("flow", p.L4FlowHash()),
					zap.String("Flags", packet.TCPFlagsToStr(p.GetTCPFlags())),
				)
			}

			cid, err := d.contextIDFromTCPPort.GetSpecValueFromPort(p.SourcePort())

			if err == nil {
				item, err := d.puFromContextID.Get(cid.(string))
				if err != nil {
					// Let the packet through if the context is not found
					return conn, nil
				}

				ctx := item.(*pucontext.PUContext)

				// Syn was not seen and this synack packet is coming from a PU
				// we monitor. This is possible only if IP is in the external
				// networks or excluded networks. Let this packet go through
				// for any of these cases. Drop for everything else.
				_, policy, perr := ctx.NetworkACLPolicyFromAddr(p.DestinationAddress(), p.SourcePort())
				if perr == nil && policy.Action.Accepted() {
					return conn, nil
				}

				// Drop this synack as it belongs to PU
				// for which we didn't see syn

				zap.L().Error("Network Syn was not seen, and we are monitoring this PU. Dropping the syn ack packet", zap.String("contextID", cid.(string)), zap.Uint16("port", p.SourcePort()))
				return conn, errNetSynNotSeen
			}

			// syn ack for non aporeto traffic can be let through
			return conn, nil
		}
	default:
		conn, err = d.appRetrieveState(p)
		if err != nil {
			if d.packetLogs {
				zap.L().Debug("Packet rejected",
					zap.String("flow", p.L4FlowHash()),
					zap.String("Flags", packet.TCPFlagsToStr(p.GetTCPFlags())),
					zap.Error(err),
				)
			}
			return conn, err
		}
	}

	conn.Lock()
	defer conn.Unlock()

	p.Print(packet.PacketStageIncoming)

	if d.service != nil {
		// PreProcessServiceInterface
		if !d.service.PreProcessTCPAppPacket(p, conn.Context, conn) {
			p.Print(packet.PacketFailureService)
			return conn, errors.New("pre service processing failed for application packet")
		}
	}

	p.Print(packet.PacketStageAuth)

	// Match the tags of the packet against the policy rules - drop if the lookup fails
	action, err := d.processApplicationTCPPacket(p, conn.Context, conn)
	if err != nil {
		if d.packetLogs {
			zap.L().Debug("Dropping packet  ",
				zap.String("flow", p.L4FlowHash()),
				zap.String("Flags", packet.TCPFlagsToStr(p.GetTCPFlags())),
				zap.Error(err),
			)
		}
		p.Print(packet.PacketFailureAuth)
		return conn, fmt.Errorf("processing failed for application packet: %s", err)
	}

	p.Print(packet.PacketStageService)

	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessTCPAppPacket(p, action, conn.Context, conn) {
			p.Print(packet.PacketFailureService)
			return conn, errors.New("post service processing failed for application packet")
		}
	}

	// Accept the packet
	p.UpdateTCPChecksum()
	p.Print(packet.PacketStageOutgoing)
	return conn, nil
}

// processApplicationTCPPacket processes a TCP packet and dispatches it to other methods based on the flags
func (d *Datapath) processApplicationTCPPacket(tcpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) (interface{}, error) {

	if conn == nil {
		return nil, nil
	}

	// State machine based on the flags
	switch tcpPacket.GetTCPFlags() & packet.TCPSynAckMask {
	case packet.TCPSynMask: //Processing SYN packet from Application
		return d.processApplicationSynPacket(tcpPacket, context, conn)

	case packet.TCPAckMask:
		return nil, d.processApplicationAckPacket(tcpPacket, context, conn)

	case packet.TCPSynAckMask:
		return nil, d.processApplicationSynAckPacket(tcpPacket, context, conn)
	default:
		return nil, nil
	}
}

// processApplicationSynPacket processes a single Syn Packet
func (d *Datapath) processApplicationSynPacket(tcpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) (interface{}, error) {

	// If the packet is not in target networks then look into the external services application cache to
	// make a decision whether the packet should be forwarded. For target networks with external services
	// network syn/ack accepts the packet if it belongs to external services.
	_, pkt, perr := d.targetNetworks.GetMatchingAction(tcpPacket.DestinationAddress(), tcpPacket.DestPort())

	if perr != nil {
		report, policy, perr := context.ApplicationACLPolicyFromAddr(tcpPacket.DestinationAddress(), tcpPacket.DestPort())

		if perr == nil && policy.Action.Accepted() {
			return nil, nil
		}

		d.reportExternalServiceFlow(context, report, pkt, true, tcpPacket)
		return nil, fmt.Errorf("No acls found for external services. Dropping application syn packet")
	}

	if policy, err := context.RetrieveCachedExternalFlowPolicy(tcpPacket.DestinationAddress().String() + ":" + strconv.Itoa(int(tcpPacket.DestPort()))); err == nil {
		d.appOrigConnectionTracker.AddOrUpdate(tcpPacket.L4FlowHash(), conn)
		d.sourcePortConnectionCache.AddOrUpdate(tcpPacket.SourcePortHash(packet.PacketTypeApplication), conn)
		return policy, nil
	}

	// We are now processing as a Trireme packet that needs authorization headers
	// Create TCP Option
	tcpOptions := d.createTCPAuthenticationOption([]byte{})

	// Create a token
	tcpData, err := d.tokenAccessor.CreateSynPacketToken(context, &conn.Auth)

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
func (d *Datapath) processApplicationSynAckPacket(tcpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) error {

	// if the traffic belongs to the same pu, let it go
	if conn.GetState() == connection.TCPData && conn.IsLoopbackConnection() {
		return nil
	}

	// If we are already in the connection.TCPData, it means that this is an external flow
	// At this point we can release the flow to the kernel by updating conntrack
	// We can also clean up the state since we are not going to see any more
	// packets from this connection.
	if conn.GetState() == connection.TCPData && !conn.ServiceConnection {
		if err := d.conntrack.UpdateApplicationFlowMark(
			tcpPacket.SourceAddress(),
			tcpPacket.DestinationAddress(),
			tcpPacket.IPProto(),
			tcpPacket.SourcePort(),
			tcpPacket.DestPort(),
			constants.DefaultConnMark,
		); err != nil {
			zap.L().Error("Failed to update conntrack entry for flow at SynAck packet",
				zap.String("context", string(conn.Auth.LocalContext)),
				zap.String("app-conn", tcpPacket.L4ReverseFlowHash()),
				zap.String("state", fmt.Sprintf("%d", conn.GetState())),
				zap.Error(err),
			)
		}

		err1 := d.netOrigConnectionTracker.Remove(tcpPacket.L4ReverseFlowHash())
		err2 := d.appReplyConnectionTracker.Remove(tcpPacket.L4FlowHash())

		if err1 != nil || err2 != nil {
			zap.L().Debug("Failed to remove cache entries")
		}

		return nil
	}

	// We now process packets that need authorization options

	// Create TCP Option
	tcpOptions := d.createTCPAuthenticationOption([]byte{})

	claimsHeader := claimsheader.NewClaimsHeader(
		claimsheader.OptionEncrypt(conn.PacketFlowPolicy.Action.Encrypted()),
	)

	tcpData, err := d.tokenAccessor.CreateSynAckPacketToken(context, &conn.Auth, claimsHeader)

	if err != nil {
		return err
	}

	// Set the state for future reference
	conn.SetState(connection.TCPSynAckSend)

	// Attach the tags to the packet
	return tcpPacket.TCPDataAttach(tcpOptions, tcpData)
}

// processApplicationAckPacket processes an application ack packet
func (d *Datapath) processApplicationAckPacket(tcpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) error {

	// Only process the first Ack of a connection. This means that we have received
	// as SynAck packet and we can now process the ACK.
	if conn.GetState() == connection.TCPSynAckReceived && tcpPacket.IsEmptyTCPPayload() {
		// Create a new token that includes the source and destinatio nonse
		// These are both challenges signed by the secret key and random for every
		// connection minimizing the chances of a replay attack
		token, err := d.tokenAccessor.CreateAckPacketToken(context, &conn.Auth)
		if err != nil {
			return err
		}

		tcpOptions := d.createTCPAuthenticationOption([]byte{})

		// Attach the tags to the packet
		if err := tcpPacket.TCPDataAttach(tcpOptions, token); err != nil {
			return err
		}

		conn.SetState(connection.TCPAckSend)

		// If its not a service connection, we release it to the kernel. Subsequent
		// packets after the first data packet, that might be already in the queue
		// will be transmitted through the kernel directly. Service connections are
		// delegated to the service module
		if !conn.ServiceConnection && tcpPacket.SourceAddress().String() != tcpPacket.DestinationAddress().String() &&
			!(tcpPacket.SourceAddress().IsLoopback() && tcpPacket.DestinationAddress().IsLoopback()) {
			if err := d.conntrack.UpdateApplicationFlowMark(
				tcpPacket.SourceAddress(),
				tcpPacket.DestinationAddress(),
				tcpPacket.IPProto(),
				tcpPacket.SourcePort(),
				tcpPacket.DestPort(),
				constants.DefaultConnMark,
			); err != nil {
				zap.L().Error("Failed to update conntrack table for flow after ack packet",
					zap.String("context", string(conn.Auth.LocalContext)),
					zap.String("app-conn", tcpPacket.L4ReverseFlowHash()),
					zap.String("state", fmt.Sprintf("%d", conn.GetState())),
					zap.Error(err),
				)
			}
		}

		return nil
	}

	// If we are already in the connection.TCPData connection just forward the packet
	if conn.GetState() == connection.TCPData {
		return nil
	}

	if conn.GetState() == connection.UnknownState {
		// Check if the destination is in the external services approved cache
		// and if yes, allow the packet to go and release the flow.
		_, policy, perr := context.ApplicationACLPolicyFromAddr(tcpPacket.DestinationAddress(), tcpPacket.DestPort())

		if perr != nil {
			// If it is an SSH PU, we let the connection go through
			// It means it is a new SSH Session connection, we mark
			// the packet and let it go through.
			if context.Type() == common.SSHSessionPU {
				if err := d.conntrack.UpdateApplicationFlowMark(
					tcpPacket.SourceAddress(),
					tcpPacket.DestinationAddress(),
					tcpPacket.IPProto(),
					tcpPacket.SourcePort(),
					tcpPacket.DestPort(),
					constants.DefaultConnMark,
				); err != nil {
					zap.L().Error("Failed to update conntrack entry for flow at Ack packet",
						zap.String("context", string(conn.Auth.LocalContext)),
						zap.String("app-conn", tcpPacket.L4ReverseFlowHash()),
						zap.String("state", fmt.Sprintf("%d", conn.GetState())),
						zap.Error(err),
					)
				}
				return nil
			}
			// Convert Ack to FinAck for all other pus
			return tcpPacket.ConvertAcktoFinAck()
		}

		if policy.Action.Rejected() {
			return errors.New("Reject the packet")
		}

		if err := d.conntrack.UpdateApplicationFlowMark(
			tcpPacket.SourceAddress(),
			tcpPacket.DestinationAddress(),
			tcpPacket.IPProto(),
			tcpPacket.SourcePort(),
			tcpPacket.DestPort(),
			constants.DefaultConnMark,
		); err != nil {
			zap.L().Error("Failed to update conntrack entry for flow at Ack packet",
				zap.String("context", string(conn.Auth.LocalContext)),
				zap.String("app-conn", tcpPacket.L4ReverseFlowHash()),
				zap.String("state", fmt.Sprintf("%d", conn.GetState())),
				zap.Error(err),
			)
		}
		return nil
	}

	// Here we capture the first data packet after an ACK packet by modyfing the
	// state. We will not release the caches though to deal with re-transmissions.
	// We will let the caches expire.
	if conn.GetState() == connection.TCPAckSend {
		conn.SetState(connection.TCPData)
		return nil
	}

	return fmt.Errorf("received application ack packet in the wrong state: %d", conn.GetState())
}

// processNetworkTCPPacket processes a network TCP packet and dispatches it to different methods based on the flags
func (d *Datapath) processNetworkTCPPacket(tcpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	if conn == nil {
		return nil, nil, nil
	}

	// Update connection state in the internal state machine tracker
	switch tcpPacket.GetTCPFlags() & packet.TCPSynAckMask {

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

	// Incoming packets that don't have our options are candidates to be processed
	// as external services.
	if err = tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {

		// If there is no auth option, attempt the ACLs
		report, pkt, perr := context.NetworkACLPolicy(tcpPacket)
		d.reportExternalServiceFlow(context, report, pkt, false, tcpPacket)
		if perr != nil || pkt.Action.Rejected() {
			return nil, nil, fmt.Errorf("no auth or acls: outgoing connection dropped: %s", perr)
		}

		conn.SetState(connection.TCPData)
		d.netOrigConnectionTracker.AddOrUpdate(tcpPacket.L4FlowHash(), conn)
		d.appReplyConnectionTracker.AddOrUpdate(tcpPacket.L4ReverseFlowHash(), conn)

		return pkt, nil, nil
	}

	// Packets that have authorization information go through the auth path
	// Decode the JWT token using the context key
	claims, err = d.tokenAccessor.ParsePacketToken(&conn.Auth, tcpPacket.ReadTCPData())
	// If the token signature is not valid, we must drop the connection and we drop the Syn packet.
	// The source will retry but we have no state to maintain here.
	if err != nil {
		d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, tokens.CodeFromErr(err), nil, nil, false)
		return nil, nil, fmt.Errorf("Syn packet dropped because of invalid token: %s", err)
	}

	// if there are no claims we must drop the connection and we drop the Syn
	// packet. The source will retry but we have no state to maintain here.
	if claims == nil {
		d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidToken, nil, nil, false)
		return nil, nil, errors.New("Syn packet dropped because of no claims")
	}

	txLabel, ok := claims.T.Get(enforcerconstants.TransmitterLabel)
	if err := tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); !ok || err != nil {
		d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID(), context, collector.InvalidFormat, nil, nil, false)
		return nil, nil, fmt.Errorf("TCP authentication option not found: %s", err)
	}

	// Remove any of our data from the packet. No matter what we don't need the
	// metadata any more.
	if err := tcpPacket.TCPDataDetach(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
		d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID(), context, collector.InvalidHeader, nil, nil, false)
		return nil, nil, fmt.Errorf("Syn packet dropped because of invalid format: %s", err)
	}

	tcpPacket.DropTCPDetachedBytes()

	// Add the port as a label with an @ prefix. These labels are invalid otherwise
	// If all policies are restricted by port numbers this will allow port-specific policies
	tags := claims.T.Copy()
	tags.AppendKeyValue(enforcerconstants.PortNumberLabelString, strconv.Itoa(int(tcpPacket.DestPort())))

	report, pkt := context.SearchRcvRules(tags)

	if pkt.Action.Rejected() && (txLabel != context.ManagementID()) {
		d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID(), context, collector.PolicyDrop, report, pkt, false)
		return nil, nil, fmt.Errorf("connection rejected because of policy: %s", tags.String())
	}

	hash := tcpPacket.L4FlowHash()
	// Update the connection state and store the Nonse send to us by the host.
	// We use the nonse in the subsequent packets to achieve randomization.
	conn.SetState(connection.TCPSynReceived)

	// conntrack
	d.netOrigConnectionTracker.AddOrUpdate(hash, conn)
	d.appReplyConnectionTracker.AddOrUpdate(tcpPacket.L4ReverseFlowHash(), conn)

	// Cache the action
	conn.ReportFlowPolicy = report
	conn.PacketFlowPolicy = pkt

	if txLabel == context.ManagementID() {
		zap.L().Debug("Traffic to the same pu", zap.String("flow", tcpPacket.L4FlowHash()))
		conn.SetLoopbackConnection(true)
	}

	// Accept the connection
	return pkt, claims, nil
}

// policyPair stores both reporting and actual action taken on packet.
type policyPair struct {
	report *policy.FlowPolicy
	packet *policy.FlowPolicy
}

// processNetworkSynAckPacket processes a SynAck packet arriving from the network
func (d *Datapath) processNetworkSynAckPacket(context *pucontext.PUContext, conn *connection.TCPConnection, tcpPacket *packet.Packet) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	// Packets with no authorization are processed as external services based on the ACLS
	if err = tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {

		if _, err := d.puFromContextID.Get(conn.Context.ID()); err != nil {
			// PU has been deleted. Ignore these packets
			return nil, nil, fmt.Errorf("PU is already dead - drop SynAck packet")
		}

		flowHash := tcpPacket.SourceAddress().String() + ":" + strconv.Itoa(int(tcpPacket.SourcePort()))
		if plci, plerr := context.RetrieveCachedExternalFlowPolicy(flowHash); plerr == nil {
			plc := plci.(*policyPair)
			d.releaseFlow(context, plc.report, plc.packet, tcpPacket)
			return plc.packet, nil, nil
		}

		// Never seen this IP before, let's parse them.
		report, pkt, perr := context.ApplicationACLPolicyFromAddr(tcpPacket.SourceAddress(), tcpPacket.SourcePort())
		if perr != nil || pkt.Action.Rejected() {
			d.reportReverseExternalServiceFlow(context, report, pkt, true, tcpPacket)
			return nil, nil, fmt.Errorf("no auth or acls: drop synack packet and connection: %s: action=%d", perr, pkt.Action)
		}

		// Added to the cache if we can accept it
		context.CacheExternalFlowPolicy(
			tcpPacket,
			&policyPair{
				report: report,
				packet: pkt,
			},
		)

		// Set the state to Data so the other state machines ignore subsequent packets
		conn.SetState(connection.TCPData)

		d.releaseFlow(context, report, pkt, tcpPacket)

		return pkt, nil, nil
	}

	// This is a corner condition. We are receiving a SynAck packet and we are in
	// a state that indicates that we have already processed one. This means that
	// our ack packet was lost. We need to revert conntrack in this case and get
	// back into the picture.
	if conn.GetState() != connection.TCPSynSend {

		// Revert the connmarks - dealing with retransmissions
		if cerr := d.conntrack.UpdateNetworkFlowMark(
			tcpPacket.SourceAddress(),
			tcpPacket.DestinationAddress(),
			tcpPacket.IPProto(),
			tcpPacket.SourcePort(),
			tcpPacket.DestPort(),
			0,
		); cerr != nil {
			zap.L().Error("Failed to update conntrack table for flow after synack packet",
				zap.String("context", string(conn.Auth.LocalContext)),
				zap.String("app-conn", tcpPacket.L4ReverseFlowHash()),
				zap.String("state", fmt.Sprintf("%d", conn.GetState())),
				zap.Error(err),
			)
		}
	}

	// Now we can process the SynAck packet with its options
	tcpData := tcpPacket.ReadTCPData()
	if len(tcpData) == 0 {
		d.reportRejectedFlow(tcpPacket, nil, context.ManagementID(), collector.DefaultEndPoint, context, collector.MissingToken, nil, nil, true)
		return nil, nil, errors.New("SynAck packet dropped because of missing token")
	}

	claims, err = d.tokenAccessor.ParsePacketToken(&conn.Auth, tcpPacket.ReadTCPData())
	if err != nil {
		d.reportRejectedFlow(tcpPacket, nil, context.ManagementID(), collector.DefaultEndPoint, context, collector.MissingToken, nil, nil, true)
		return nil, nil, fmt.Errorf("SynAck packet dropped because of bad claims: %s", err)
	}

	if claims == nil {
		d.reportRejectedFlow(tcpPacket, nil, context.ManagementID(), collector.DefaultEndPoint, context, collector.MissingToken, nil, nil, true)
		return nil, nil, errors.New("SynAck packet dropped because of no claims")
	}

	tcpPacket.ConnectionMetadata = &conn.Auth

	if err := tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
		d.reportRejectedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID(), context, collector.InvalidHeader, nil, nil, true)
		return nil, nil, errors.New("TCP authentication option not found")
	}

	// Remove any of our data
	if err := tcpPacket.TCPDataDetach(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
		d.reportRejectedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID(), context, collector.InvalidPayload, nil, nil, true)
		return nil, nil, fmt.Errorf("SynAck packet dropped because of invalid format: %s", err)
	}

	tcpPacket.DropTCPDetachedBytes()

	if !d.mutualAuthorization {
		// If we dont do mutual authorization, dont lookup txt rules.
		conn.SetState(connection.TCPSynAckReceived)

		// conntrack
		d.netReplyConnectionTracker.AddOrUpdate(tcpPacket.L4FlowHash(), conn)
		return nil, claims, nil
	}

	report, pkt := context.SearchTxtRules(claims.T, !d.mutualAuthorization)

	// Report and release traffic belonging to the same pu
	if conn.Auth.RemoteContextID == context.ManagementID() {
		conn.SetState(connection.TCPData)
		conn.SetLoopbackConnection(true)
		d.reportAcceptedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID(), context, nil, nil, true)
		d.releaseUnmonitoredFlow(tcpPacket)
		return nil, nil, nil
	}

	// NOTE: For backward compatibility, remove this check later
	if claims.H != nil {
		if claims.H.ToClaimsHeader().Encrypt() != pkt.Action.Encrypted() {
			d.reportRejectedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID(), context, collector.EncryptionMismatch, nil, nil, true)
			return nil, nil, fmt.Errorf("syn/ack packet dropped because of encryption mismatch")
		}
	}

	if pkt.Action.Rejected() {
		d.reportRejectedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID(), context, collector.PolicyDrop, report, pkt, true)
		return nil, nil, fmt.Errorf("dropping because of reject rule on transmitter: %s", claims.T.String())
	}

	conn.SetState(connection.TCPSynAckReceived)

	// conntrack
	d.netReplyConnectionTracker.AddOrUpdate(tcpPacket.L4FlowHash(), conn)
	return pkt, claims, nil
}

// processNetworkAckPacket processes an Ack packet arriving from the network
func (d *Datapath) processNetworkAckPacket(context *pucontext.PUContext, conn *connection.TCPConnection, tcpPacket *packet.Packet) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	if conn.GetState() == connection.TCPData || conn.GetState() == connection.TCPAckSend {
		return nil, nil, nil
	}

	if conn.IsLoopbackConnection() {
		conn.SetState(connection.TCPData)
		d.releaseUnmonitoredFlow(tcpPacket)
		return nil, nil, nil
	}

	if conn.GetState() == connection.UnknownState {
		// Check if the destination is in the external servicess approved cache
		// and if yes, allow the packet to go and release the flow.
		_, plcy, perr := context.NetworkACLPolicy(tcpPacket)

		// Ignore FIN packets. Let them go through.
		if tcpPacket.GetTCPFlags()&packet.TCPFinMask != 0 {
			return nil, nil, nil
		}
		if perr != nil {
			err := tcpPacket.ConvertAcktoFinAck()
			return nil, nil, err
		}

		if plcy.Action.Rejected() {
			return nil, nil, errRejectPacket

		}

		if err := d.conntrack.UpdateNetworkFlowMark(
			tcpPacket.SourceAddress(),
			tcpPacket.DestinationAddress(),
			tcpPacket.IPProto(),
			tcpPacket.SourcePort(),
			tcpPacket.DestPort(),
			constants.DefaultConnMark,
		); err != nil && !netlink.IsNotExist(errors.Cause(err)) {
			zap.L().Error("Failed to update conntrack entry for flow at network Ack packet",
				zap.String("context", string(conn.Auth.LocalContext)),
				zap.String("app-conn", tcpPacket.L4ReverseFlowHash()),
				zap.String("state", fmt.Sprintf("%d", conn.GetState())),
				zap.Error(err),
			)
		}

		return nil, nil, nil
	}

	hash := tcpPacket.L4FlowHash()

	// Validate that the source/destination nonse matches. The signature has validated both directions
	if conn.GetState() == connection.TCPSynAckSend || conn.GetState() == connection.TCPSynReceived {

		if err := tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
			// TODO: this needs to be converted to a rejected packet messages. It doesn't mean rejected flow. Disabling.
			// d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidHeader, nil, nil)
			return nil, nil, errTCPAuthNotFound
		}

		if _, err := d.tokenAccessor.ParseAckToken(&conn.Auth, tcpPacket.ReadTCPData()); err != nil {
			d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidToken, nil, nil, false)
			zap.L().Debug("Ack Packet dropped because signature validation failed", zap.Error(err))
			return nil, nil, errSigValidFailed
		}

		// Remove any of our data - adjust the sequence numbers
		if err := tcpPacket.TCPDataDetach(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
			d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidPayload, nil, nil, false)
			zap.L().Debug("Error: Ack packet dropped because of invalid format", zap.Error(err))
			return nil, nil, errInvalidFormat
		}

		tcpPacket.DropTCPDetachedBytes()

		if conn.PacketFlowPolicy != nil && conn.PacketFlowPolicy.Action.Rejected() {
			if !conn.PacketFlowPolicy.ObserveAction.Observed() {
				zap.L().Error("Flow rejected but not observed", zap.String("conn", context.ManagementID()))
			}
			// Flow has been allowed because we are observing a deny rule's impact on the system. Packets are forwarded, reported as dropped + observed.
			d.reportRejectedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID(), context, collector.PolicyDrop, conn.ReportFlowPolicy, conn.PacketFlowPolicy, false)
		} else {
			// We accept the packet as a new flow
			d.reportAcceptedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID(), context, conn.ReportFlowPolicy, conn.PacketFlowPolicy, false)
		}

		conn.SetState(connection.TCPData)

		if !conn.ServiceConnection {
			if err := d.conntrack.UpdateNetworkFlowMark(
				tcpPacket.SourceAddress(),
				tcpPacket.DestinationAddress(),
				tcpPacket.IPProto(),
				tcpPacket.SourcePort(),
				tcpPacket.DestPort(),
				constants.DefaultConnMark,
			); err != nil {
				zap.L().Error("Failed to update conntrack table after ack packet",
					zap.String("app-conn", tcpPacket.L4ReverseFlowHash()))
			}
		}

		// Accept the packet
		return nil, nil, nil
	}

	if conn.ServiceConnection {
		return nil, nil, nil
	}

	// Everything else is dropped - ACK received in the Syn state without a SynAck
	d.reportRejectedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID(), context, collector.InvalidState, nil, nil, false)
	zap.L().Error("Invalid state reached",
		zap.String("state", fmt.Sprintf("%d", conn.GetState())),
		zap.String("context", context.ManagementID()),
		zap.String("net-conn", hash),
	)

	return nil, nil, errInvalidConnState
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
func (d *Datapath) appSynRetrieveState(p *packet.Packet) (*connection.TCPConnection, error) {

	context, err := d.contextFromIP(true, p.Mark, p.SourcePort(), packet.IPProtocolTCP)
	if err != nil {
		return nil, err
	}

	if conn, err := d.appOrigConnectionTracker.GetReset(p.L4FlowHash(), 0); err == nil {
		return conn.(*connection.TCPConnection), nil
	}
	return connection.NewTCPConnection(context, p), nil
}

// appSynAckRetrieveState retrieves the state for application syn/ack packet.
func (d *Datapath) appSynAckRetrieveState(p *packet.Packet) (*connection.TCPConnection, error) {
	hash := p.L4FlowHash()

	// Did we see a network syn for this server PU?
	conn, err := d.appReplyConnectionTracker.GetReset(hash, 0)
	if err != nil {
		return nil, errNetSynNotSeen
	}

	if uerr := updateTimer(d.appReplyConnectionTracker, hash, conn.(*connection.TCPConnection)); uerr != nil {
		zap.L().Error("entry expired just before updating the timer", zap.String("flow", hash))
		return nil, uerr
	}

	return conn.(*connection.TCPConnection), nil
}

// appRetrieveState retrieves the state for the rest of the application packets. It
// returns an error if it cannot find the state
func (d *Datapath) appRetrieveState(p *packet.Packet) (*connection.TCPConnection, error) {
	hash := p.L4FlowHash()

	// If this ack packet is from Server, Did we see a network Syn for this server PU?
	conn, err := d.appReplyConnectionTracker.GetReset(hash, 0)
	if err == nil {
		if uerr := updateTimer(d.appReplyConnectionTracker, hash, conn.(*connection.TCPConnection)); uerr != nil {
			zap.L().Error("entry expired just before updating the timer", zap.String("flow", hash))
			return nil, uerr
		}

		return conn.(*connection.TCPConnection), nil
	}

	// If this ack packet is from client, Did we see an Application Syn packet before?
	conn, err = d.appOrigConnectionTracker.GetReset(hash, 0)
	if err == nil {
		if uerr := updateTimer(d.appOrigConnectionTracker, hash, conn.(*connection.TCPConnection)); uerr != nil {
			return nil, uerr
		}
		return conn.(*connection.TCPConnection), nil
	}

	if p.GetTCPFlags()&packet.TCPSynAckMask == packet.TCPAckMask {
		// Let's try if its an existing connection
		context, err := d.contextFromIP(true, p.Mark, p.SourcePort(), packet.IPProtocolTCP)
		if err != nil {
			return nil, errors.New("No context in app processing")
		}
		conn = connection.NewTCPConnection(context, p)
		conn.(*connection.TCPConnection).SetState(connection.UnknownState)
		return conn.(*connection.TCPConnection), nil
	}

	return nil, errNoConnFound
}

// netSynRetrieveState retrieves the state for the Syn packets on the network.
// Obviously if no state is found, it generates a new connection record.
func (d *Datapath) netSynRetrieveState(p *packet.Packet) (*connection.TCPConnection, error) {

	context, err := d.contextFromIP(false, p.Mark, p.DestPort(), packet.IPProtocolTCP)
	if err == nil {
		if conn, err := d.netOrigConnectionTracker.GetReset(p.L4FlowHash(), 0); err == nil {
			return conn.(*connection.TCPConnection), nil
		}
		return connection.NewTCPConnection(context, p), nil
	}

	//This needs to hit only for local processes never for containers
	//Don't return an error create a dummy context and return it so we truncate the packet before we send it up
	if d.mode != constants.RemoteContainer {

		//we will create the bare minimum needed to exercise our stack
		//We need this syn to look similar to what we will pass on the retry
		//so we setup enough for us to identify this request in the later stages

		// Remove any of our data from the packet.
		if err = p.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
			zap.L().Error("Syn received with tcp option not set", zap.Error(err))
			return nil, errNonPUTraffic
		}

		if err = p.TCPDataDetach(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
			zap.L().Error("Error removing TCP Data", zap.Error(err))
			return nil, errNonPUTraffic
		}

		p.DropTCPDetachedBytes()

		p.UpdateTCPChecksum()

		return nil, errNonPUTraffic
	}
	return connection.NewTCPConnection(context, p), nil
}

// netSynAckRetrieveState retrieves the state for SynAck packets at the network
// It relies on the source port cache for that
func (d *Datapath) netSynAckRetrieveState(p *packet.Packet) (*connection.TCPConnection, error) {

	conn, err := d.sourcePortConnectionCache.GetReset(p.SourcePortHash(packet.PacketTypeNetwork), 0)
	if err != nil {
		return nil, errNonPUTraffic
	}

	return conn.(*connection.TCPConnection), nil
}

// netRetrieveState retrieves the state of a network connection. Use the flow caches for that
func (d *Datapath) netRetrieveState(p *packet.Packet) (*connection.TCPConnection, error) {
	hash := p.L4FlowHash()

	// Did we see a network syn/ack packet? (PU is a client)
	conn, err := d.netReplyConnectionTracker.GetReset(hash, 0)
	if err == nil {
		if err = updateTimer(d.netReplyConnectionTracker, hash, conn.(*connection.TCPConnection)); err != nil {
			return nil, err
		}

		return conn.(*connection.TCPConnection), nil
	}

	// Did we see a network Syn packet before? (PU is a server)
	conn, err = d.netOrigConnectionTracker.GetReset(hash, 0)
	if err == nil {
		if err = updateTimer(d.netOrigConnectionTracker, hash, conn.(*connection.TCPConnection)); err != nil {
			return nil, err
		}

		return conn.(*connection.TCPConnection), nil
	}

	// We reach in this state for a client PU only when the service connection(encrypt) sends data sparsely.
	// Packets are dropped when this happens, and that is a BUG!!!
	// For the server PU we mark the connection in the unknown state.
	if p.GetTCPFlags()&packet.TCPSynAckMask == packet.TCPAckMask {
		// Let's try if its an existing connection
		context, cerr := d.contextFromIP(false, p.Mark, p.DestPort(), packet.IPProtocolTCP)
		if cerr != nil {
			return nil, err
		}
		conn = connection.NewTCPConnection(context, p)
		conn.(*connection.TCPConnection).SetState(connection.UnknownState)
		return conn.(*connection.TCPConnection), nil
	}

	return nil, errInvalidNetState
}

// updateTimer updates the timers for the service connections
func updateTimer(c cache.DataStore, hash string, conn *connection.TCPConnection) error {
	conn.RLock()
	defer conn.RUnlock()

	if conn.ServiceConnection && conn.TimeOut > 0 {
		return c.SetTimeOut(hash, conn.TimeOut)
	}
	return nil
}

// releaseFlow releases the flow and updates the conntrack table
func (d *Datapath) releaseFlow(context *pucontext.PUContext, report *policy.FlowPolicy, action *policy.FlowPolicy, tcpPacket *packet.Packet) {

	if err := d.appOrigConnectionTracker.Remove(tcpPacket.L4ReverseFlowHash()); err != nil {
		zap.L().Debug("Failed to clean cache appOrigConnectionTracker", zap.Error(err))
	}

	if err := d.sourcePortConnectionCache.Remove(tcpPacket.SourcePortHash(packet.PacketTypeNetwork)); err != nil {
		zap.L().Debug("Failed to clean cache sourcePortConnectionCache", zap.Error(err))
	}

	if err := d.conntrack.UpdateNetworkFlowMark(
		tcpPacket.SourceAddress(),
		tcpPacket.DestinationAddress(),
		tcpPacket.IPProto(),
		tcpPacket.SourcePort(),
		tcpPacket.DestPort(),
		constants.DefaultConnMark,
	); err != nil {
		zap.L().Error("Failed to update conntrack table",
			zap.String("app-conn", tcpPacket.L4ReverseFlowHash()),
			zap.Error(err))
	}

	d.reportReverseExternalServiceFlow(context, report, action, true, tcpPacket)
}

// releaseUnmonitoredFlow releases the flow and updates the conntrack table
func (d *Datapath) releaseUnmonitoredFlow(tcpPacket *packet.Packet) {

	zap.L().Debug("Releasing flow", zap.String("flow", tcpPacket.L4FlowHash()))
	if err := d.conntrack.UpdateNetworkFlowMark(
		tcpPacket.SourceAddress(),
		tcpPacket.DestinationAddress(),
		tcpPacket.IPProto(),
		tcpPacket.SourcePort(),
		tcpPacket.DestPort(),
		constants.DefaultConnMark,
	); err != nil && !netlink.IsNotExist(errors.Cause(err)) {
		zap.L().Error("Failed to update conntrack table", zap.Error(err))
	}
}
