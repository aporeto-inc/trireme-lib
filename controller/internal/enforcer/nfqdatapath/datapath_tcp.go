package nfqdatapath

// Go libraries
import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/pkg/errors"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	enforcerconstants "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/counters"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/tokens"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.uber.org/zap"
)

var (
	errNonPUTraffic     = errors.New("not a pu traffic")
	errNonPUUDPTraffic  = errors.New("not a pu udp traffic")
	errOutOfOrderSynAck = errors.New("out of order syn ack packet")
	errRstPacket        = errors.New("rst packet")
	errNoConnection     = errors.New("no connection found")

	// Custom ping error types
	errDropPingNetSynAck = errors.New("net synack dropped")
	errDropPingNetSyn    = errors.New("net syn dropped") // nolint: varcheck

	rstIdentity = []byte("enforcerrstidentity")
)

// processNetworkPackets processes packets arriving from network and are destined to the application
func (d *Datapath) processNetworkTCPPackets(p *packet.Packet) (*connection.TCPConnection, func(), error) {
	var conn *connection.TCPConnection
	var err error
	var f func()

	debugLogs := func(debugString string) {

		if d.PacketLogsEnabled() {
			zap.L().Debug(debugString,
				zap.String("flow", p.L4FlowHash()),
				zap.String("Flags", packet.TCPFlagsToStr(p.GetTCPFlags())),
				zap.Error(err))
		}
	}

	// Retrieve connection state of SynAck packets and
	// skip processing for SynAck packets that we don't have state
	switch p.GetTCPFlags() & packet.TCPSynAckMask {
	case packet.TCPSynMask:
		conn, err = d.netSynRetrieveState(p)
		if err != nil {
			switch err {
			// Non PU Traffic let it through
			case errNonPUTraffic:
				return conn, nil, nil
			default:
				debugLogs("Packet rejected")
				return conn, nil, err
			}
		}

	case packet.TCPSynAckMask:
		conn, err = d.netSynAckRetrieveState(p)
		if err != nil {
			switch err {
			case errOutOfOrderSynAck:
				// Drop this synack it is for a flow we know which is marked for deletion.
				// We saw a FINACK and this synack has come without we seeing an appsyn for this flow again
				return conn, nil, counters.CounterError(counters.ErrOutOfOrderSynAck, fmt.Errorf("ErrOutOfOrderSynAck"))
			default:
				d.releaseUnmonitoredFlow(p)
				return conn, nil, nil
			}
		}

	default:
		conn, err = d.netRetrieveState(p)
		switch err {
		case nil:
			// Do nothing.
		case errRstPacket:
			return conn, nil, nil
		default:
			debugLogs("Packet rejected")
			return conn, nil, err
		}
	}

	conn.Lock()
	defer conn.Unlock()

	if conn.GetState() == connection.TCPSynSend && p.GetTCPFlags()&packet.TCPRstMask != 0 && !conn.PingEnabled() {
		p.TCPDataDetach(0)
		d.cacheRemove(d.tcpClient, p.L4ReverseFlowHash())
		return conn, f, nil
	}

	f, err = d.processNetworkTCPPacket(p, conn.Context, conn)
	if err != nil {
		debugLogs("Rejecting packet")
		return conn, nil, err
	}
	return conn, f, nil
}

// processApplicationPackets processes packets arriving from an application and are destined to the network
func (d *Datapath) processApplicationTCPPackets(p *packet.Packet) (conn *connection.TCPConnection, err error) {

	debugLogs := func(debugString string) {
		if d.PacketLogsEnabled() {
			zap.L().Debug(debugString,
				zap.String("flow", p.L4FlowHash()),
				zap.String("Flags", packet.TCPFlagsToStr(p.GetTCPFlags())),
				zap.Error(err),
			)
		}
	}

	switch p.GetTCPFlags() & packet.TCPSynAckMask {
	case packet.TCPSynMask:
		conn, err = d.appSynRetrieveState(p)
		if err != nil {
			debugLogs("Packet rejected")
			return conn, err
		}
	case packet.TCPSynAckMask:
		conn, err = d.appSynAckRetrieveState(p)
		if err != nil {
			debugLogs("SynAckPacket Ignored")
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
				_, policy, perr := ctx.NetworkACLPolicyFromAddr(p.DestinationAddress(), p.SourcePort(), p.IPProto())
				if perr == nil && policy.Action.Accepted() {
					ctx.Counters().IncrementCounter(counters.ErrSynAckToExtNetAccept)
					return conn, nil
				}

				// Drop this synack as it belongs to PU
				// for which we didn't see syn

				// FYI.  This can happen when the enforcer is starting. The syn packet gets by the enforcer but is then caught here.
				zap.L().Debug("Network Syn was not seen, and we are monitoring this PU. Dropping the syn ack packet", zap.String("contextID", cid.(string)), zap.Uint16("port", p.SourcePort()))
				return conn, counters.CounterError(counters.ErrNetSynNotSeen, fmt.Errorf("Network Syn was not seen"))
			}

			// syn ack for non aporeto traffic can be let through
			return conn, nil
		}
	default:
		conn, err = d.appRetrieveState(p)
		if err == errRstPacket {
			return nil, nil
		}

		if err != nil {
			debugLogs("Packet rejected")
			return conn, err
		}
	}

	conn.Lock()
	defer conn.Unlock()

	if conn.GetState() == connection.TCPSynReceived && p.GetTCPFlags()&packet.TCPRstMask != 0 && !conn.PingEnabled() {
		// Seen a RST packet. Remove cache entries related to this connection
		p.TCPDataDetach(0)
		d.cacheRemove(d.tcpServer, p.L4ReverseFlowHash())
		return conn, nil
	}

	err = d.processApplicationTCPPacket(p, conn.Context, conn)
	if err != nil {
		debugLogs("Dropping packet")
		return conn, err
	}

	return conn, nil
}

// processApplicationTCPPacket processes a TCP packet and dispatches it to other methods based on the flags
func (d *Datapath) processApplicationTCPPacket(tcpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) error {

	// State machine based on the flags
	switch tcpPacket.GetTCPFlags() & packet.TCPSynAckMask {
	case packet.TCPSynMask: //Processing SYN packet from Application
		return d.processApplicationSynPacket(tcpPacket, context, conn)

	case packet.TCPAckMask:
		if tcpPacket.GetTCPFlags()&packet.TCPFinMask != 0 {
			conn.MarkForDeletion = true
		}
		return d.processApplicationAckPacket(tcpPacket, context, conn)

	case packet.TCPSynAckMask:
		return d.processApplicationSynAckPacket(tcpPacket, context, conn)
	default:
		return nil
	}
}

// processApplicationSynPacket processes a single Syn Packet
func (d *Datapath) processApplicationSynPacket(tcpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) error {
	// Increment the counter.
	conn.IncrementCounter()

	if err := tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err == nil {
		conn.Context.Counters().IncrementCounter(counters.ErrAppSynAuthOptionSet)
	}

	var tcpData []byte

	conn.Secrets, conn.Auth.LocalDatapathPrivateKey, tcpData = context.GetSynToken(nil, conn.Auth.Nonce, nil)

	buffer := append(tcpPacket.GetBuffer(0), []byte{packet.TCPAuthenticationOption, enforcerconstants.TCPAuthenticationOptionBaseLen, 0, 0}...)
	buffer = append(buffer, tcpData...)
	// Attach the tags to the packet and accept the packet
	if err := tcpPacket.UpdatePacketBuffer(buffer, enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
		return err
	}

	// Set the state indicating that we send out a Syn packet
	conn.SetState(connection.TCPSynSend)
	d.cachePut(d.tcpClient, tcpPacket.L4FlowHash(), conn)

	// Attach the tags to the packet and accept the packet
	return nil
}

// processApplicationSynAckPacket processes an application SynAck packet
func (d *Datapath) processApplicationSynAckPacket(tcpPacket *packet.Packet, _ *pucontext.PUContext, conn *connection.TCPConnection) error {
	// if the traffic belongs to the same pu, let it go
	if conn.GetState() == connection.TCPData && conn.IsLoopbackConnection() {
		return nil
	}

	// If we are already in the connection.TCPData, it means that this is an external flow
	// At this point we can release the flow to the kernel by updating conntrack
	// We can also clean up the state since we are not going to see any more
	// packets from this connection.
	if conn.GetState() == connection.TCPData {
		// remove from our tcp server cache
		d.cacheRemove(d.tcpServer, tcpPacket.L4ReverseFlowHash())

		if err := d.ignoreFlow(tcpPacket); err != nil {
			zap.L().Error("Failed to ignore flow", zap.Error(err))
		}
		tcpPacket.SetConnmark = true
		return nil
	}

	if err := tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err == nil {
		conn.Context.Counters().IncrementCounter(counters.ErrAppSynAckAuthOptionSet)
	}

	buffer := append(tcpPacket.GetBuffer(0), []byte{packet.TCPAuthenticationOption, enforcerconstants.TCPAuthenticationOptionBaseLen, 0, 0}...)
	buffer = append(buffer, conn.Auth.SynAckToken...)
	if err := tcpPacket.UpdatePacketBuffer(buffer, enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
		return err
	}

	conn.SetState(connection.TCPSynAckSend)
	return nil
}

// processApplicationAckPacket processes an application ack packet
func (d *Datapath) processApplicationAckPacket(tcpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) error {
	// Only process the first Ack of a connection. This means that we have received
	// as SynAck packet and we can now process the ACK.
	if conn.GetState() == connection.TCPSynAckReceived {

		// Special case. We are handling an AP packet with data, but the ACK has been lost
		// somewhere. In this case, we drop the payload and send our authorization data.
		// The TCP stack will try again.
		if !tcpPacket.IsEmptyTCPPayload() {
			tcpPacket.TCPDataDetach(0)
		}

		buffer := append(tcpPacket.GetBuffer(0), []byte{packet.TCPAuthenticationOption, enforcerconstants.TCPAuthenticationOptionBaseLen, 0, 0}...)
		buffer = append(buffer, conn.Auth.AckToken...)
		if err := tcpPacket.UpdatePacketBuffer(buffer, enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
			return err
		}

		conn.SetState(connection.TCPAckSend)

		return nil
	}

	// If we are already in the connection.TCPData connection just forward the packet
	if conn.GetState() == connection.TCPData {
		return nil
	}

	if conn.GetState() == connection.UnknownState {
		// Check if the destination is in the external services approved cache
		// and if yes, allow the packet to go and release the flow.
		_, policy, perr := context.ApplicationACLPolicyFromAddr(tcpPacket.DestinationAddress(), tcpPacket.DestPort(), tcpPacket.IPProto())

		if perr != nil {
			conn.Context.Counters().CounterError(counters.ErrAckInUnknownState, nil) //nolint
			zap.L().Debug("converting to rst app",
				zap.String("SourceIP", tcpPacket.SourceAddress().String()),
				zap.String("DestinationIP", tcpPacket.DestinationAddress().String()),
				zap.Int("SourcePort", int(tcpPacket.SourcePort())),
				zap.Int("DestinationPort", int(tcpPacket.DestPort())),
				zap.String("Flags", packet.TCPFlagsToStr(tcpPacket.GetTCPFlags())),
			)
			tcpPacket.ConvertToRst()
			tcpPacket.SetConnmark = true
			return nil
		}

		if policy.Action.Rejected() {
			return conn.Context.Counters().CounterError(counters.ErrRejectPacket, fmt.Errorf("Rejected due to policy %s", policy.PolicyID))
		}
		if err := d.ignoreFlow(tcpPacket); err != nil {
			zap.L().Error("Failed to ignore flow", zap.Error(err))
		}
		tcpPacket.SetConnmark = true
		return nil
	}

	// Here we capture the first data packet after an ACK packet by modyfing the
	// state. We will not release the caches though to deal with re-transmissions.
	// We will let the caches expire.
	if conn.GetState() == connection.TCPAckSend {
		if tcpPacket.SourceAddress().String() != tcpPacket.DestinationAddress().String() &&
			!(tcpPacket.SourceAddress().IsLoopback() && tcpPacket.DestinationAddress().IsLoopback()) {

			if err := d.ignoreFlow(tcpPacket); err != nil {
				zap.L().Error("Failed to ignore flow", zap.Error(err))
			}

			conn.ResetTimer(waitBeforeRemovingConn)
			tcpPacket.SetConnmark = true
			counters.IncrementCounter(counters.ErrConnectionsProcessed)
		}
		conn.SetState(connection.TCPData)
		return nil
	}

	return fmt.Errorf("received application ack packet in the wrong state: %d", conn.GetState())
}

// processNetworkTCPPacket processes a network TCP packet and dispatches it to different methods based on the flags
func (d *Datapath) processNetworkTCPPacket(tcpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) (func(), error) {

	// Update connection state in the internal state machine tracker
	switch tcpPacket.GetTCPFlags() & packet.TCPSynAckMask {

	case packet.TCPSynMask:
		return d.processNetworkSynPacket(context, conn, tcpPacket)

	case packet.TCPAckMask:
		if tcpPacket.GetTCPFlags()&packet.TCPFinMask == packet.TCPFinMask {
			conn.MarkForDeletion = true
		}
		return nil, d.processNetworkAckPacket(context, conn, tcpPacket)
	case packet.TCPSynAckMask:
		return d.processNetworkSynAckPacket(context, conn, tcpPacket)

	default: // Ignore any other packet
		return nil, nil
	}
}

func (d *Datapath) clientIdentityAllowed(context *pucontext.PUContext, token []byte, tcpPacket *packet.Packet, conn *connection.TCPConnection, networkReport *policy.FlowPolicy) error {

	claims := &conn.Auth.ConnectionClaims
	secretKey, claimsHeader, controller, remoteNonce, remoteContextID, proto314, err := d.tokenAccessor.ParsePacketToken(conn.Auth.LocalDatapathPrivateKey, token, conn.Secrets, claims, false)

	if err != nil {
		zap.L().Error("Syn token Parse Error", zap.String("flow", tcpPacket.L4FlowHash()), zap.Error(err))
		d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidToken, nil, nil, false)
		return conn.Context.Counters().CounterError(netSynCounterFromError(err), err)
	}

	conn.Auth.SecretKey = secretKey
	conn.Auth.RemoteNonce = remoteNonce
	conn.Auth.RemoteContextID = remoteContextID
	conn.Auth.Proto314 = proto314

	if controller != nil &&
		((!controller.SameController) ||
			(claimsHeader != nil && claimsHeader.Ping())) {
		conn.SourceController = controller.Controller
	}

	txLabel, ok := claims.T.Get(enforcerconstants.TransmitterLabel)
	if !ok {
		d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID(), context, collector.InvalidFormat, nil, nil, false)
		return conn.Context.Counters().CounterError(counters.ErrSynDroppedTCPOption, fmt.Errorf("ErrSynDroppedTCPOption"))
	}

	// Add the port as a label with an @ prefix. These labels are invalid otherwise
	// If all policies are restricted by port numbers this will allow port-specific policies
	tags := claims.T.Copy()
	tags.AppendKeyValue(constants.PortNumberLabelString, fmt.Sprintf("%s/%s", constants.TCPProtoString, strconv.Itoa(int(tcpPacket.DestPort()))))

	// Add the controller to the claims
	if controller != nil && len(controller.Controller) > 0 {
		tags.AppendKeyValue(constants.ControllerLabelString, controller.Controller)
	}

	report, pkt := context.SearchRcvRules(tags)

	// If we have an ObserveContinue Rejected ACL, then report this as the observed flow.
	if networkReport != nil && networkReport.Action.Rejected() && networkReport.ObserveAction.ObserveContinue() {
		report = networkReport
	}

	conn.ReportFlowPolicy = report
	conn.PacketFlowPolicy = pkt

	if claimsHeader != nil && claimsHeader.Ping() && claims.P != nil {
		err := d.processPingNetSynPacket(context, conn, tcpPacket, len(token), pkt, claims)
		if err != nil && err != errDropPingNetSyn {
			zap.L().Error("unable to process ping network syn", zap.Error(err))
		}
		return err
	}

	allow := false
	if txLabel == context.ManagementID() {
		zap.L().Debug("Traffic to the same pu", zap.String("flow", tcpPacket.L4FlowHash()))
		conn.SetLoopbackConnection(true)
		allow = true
	}

	if !pkt.Action.Rejected() || allow {
		return nil
	}

	// TODO: Support ipv6
	if tcpPacket.IPversion() == packet.V4 {
		go func() {
			if err := respondWithRstPacket(tcpPacket, rstIdentity); err != nil {
				zap.L().Warn("unable to send rst packet", zap.Error(err))
			}
		}()
	}

	d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID(), context, collector.PolicyDrop, report, pkt, false)
	return conn.Context.Counters().CounterError(counters.ErrSynRejectPacket, fmt.Errorf("PolicyDrop %s", pkt.PolicyID))
}

// processNetworkSynPacket processes a syn packet arriving from the network
func (d *Datapath) processNetworkSynPacket(context *pucontext.PUContext, conn *connection.TCPConnection, tcpPacket *packet.Packet) (func(), error) {
	var err error
	conn.IncrementCounter()

	createSynAckToken := func() {
		var pingPayload *policy.PingPayload
		claimsHeader := claimsheader.NewClaimsHeader()

		// This means we got syn with ping header set and passthrough enabled.
		// The application responds with synack.
		if conn.PingEnabled() {
			pingPayload = &policy.PingPayload{}
			conn.PingConfig.SetApplicationListening(true)
			pingPayload.PingID = conn.PingConfig.PingID()
			pingPayload.IterationID = conn.PingConfig.IterationID()
			pingPayload.ApplicationListening = true
			pingPayload.NamespaceHash = context.ManagementNamespaceHash()
			claimsHeader.SetPing(true)
		}

		claims := &tokens.ConnectionClaims{
			CT:       context.CompressedTags(),
			LCL:      conn.Auth.Nonce[:],
			RMT:      conn.Auth.RemoteNonce,
			DEKV1:    conn.Auth.LocalDatapathPublicKeyV1,
			SDEKV1:   conn.Auth.LocalDatapathPublicKeySignV1,
			DEKV2:    conn.Auth.LocalDatapathPublicKeyV2,
			SDEKV2:   conn.Auth.LocalDatapathPublicKeySignV2,
			ID:       context.ManagementID(),
			RemoteID: conn.Auth.RemoteContextID,
			P:        pingPayload,
		}

		if conn.Auth.SynAckToken, err = d.tokenAccessor.CreateSynAckPacketToken(conn.Auth.Proto314, claims, conn.EncodedBuf[:], conn.Auth.Nonce[:], claimsHeader, conn.Secrets, conn.Auth.SecretKey); err != nil {
			zap.L().Error("Syn/Ack token create failed", zap.String("flow", tcpPacket.L4FlowHash()), zap.Error(err))
			conn.Context.Counters().CounterError(appSynCounterFromError(err), err) //nolint
		}
	}

	allowPkt := func() {
		tcpPacket.TCPDataDetach(enforcerconstants.TCPAuthenticationOptionBaseLen) //nolint
		conn.SetState(connection.TCPSynReceived)
		d.cachePut(d.tcpServer, tcpPacket.L4FlowHash(), conn)
	}

	// We should only be here if we have identity
	if err = tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil || (err == nil && tcpPacket.IsEmptyTCPPayload()) {
		// This is not a normal case and should never happen because Linux/Windows rules are checking for this before sending the packet to NFQ.
		if err == nil {
			err = fmt.Errorf("identity payload empty: incoming connection dropped")
		} else {
			err = fmt.Errorf("invalid identity: incoming connection dropped: %s", err)
		}
		d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.MissingToken, nil, nil, false)
		return nil, context.Counters().CounterError(counters.ErrSynMissingTCPOption, err)
	}

	rejected := false
	networkReport, pkt, perr := context.NetworkACLPolicy(tcpPacket)
	if perr == nil {
		rejected = pkt.Action.Rejected()
		if rejected {
			perr = fmt.Errorf("rejected by ACL policy %s", pkt.PolicyID)
		}
	} else {
		// We got an error, but ensure it isn't the catch all policy
		if !(pkt != nil && pkt.Action.Rejected() && pkt.PolicyID == "default") {
			rejected = true
		}
	}

	if rejected {
		d.reportExternalServiceFlow(context, networkReport, pkt, false, tcpPacket)
		return nil, context.Counters().CounterError(counters.ErrSynFromExtNetReject, fmt.Errorf("packet had identity: incoming connection dropped: %s", perr))
	}

	token := tcpPacket.ReadTCPData()

	if err = d.clientIdentityAllowed(context, token, tcpPacket, conn, networkReport); err == nil {
		processAfterVerdict := func() {
			createSynAckToken()
		}

		allowPkt()
		return processAfterVerdict, nil
	}

	return nil, err
}

// policyPair stores both reporting and actual action taken on packet.
type policyPair struct {
	report *policy.FlowPolicy
	packet *policy.FlowPolicy
}

// processNetworkSynAckPacket processes a SynAck packet arriving from the network
func (d *Datapath) processNetworkSynAckPacket(context *pucontext.PUContext, conn *connection.TCPConnection, tcpPacket *packet.Packet) (func(), error) {
	var err error

	allowPkt := func() {
		// Remove any of our data
		conn.SetState(connection.TCPSynAckReceived)
		tcpPacket.TCPDataDetach(enforcerconstants.TCPAuthenticationOptionBaseLen) //nolint
	}

	createAckToken := func() {
		claims := &tokens.ConnectionClaims{
			ID:       context.ManagementID(),
			RMT:      conn.Auth.RemoteNonce,
			RemoteID: conn.Auth.RemoteContextID,
		}

		// Create a new token that includes the source and destinatio nonce
		// These are both challenges signed by the secret key and random for every
		// connection minimizing the chances of a replay attack
		if conn.Auth.AckToken, err = d.tokenAccessor.CreateAckPacketToken(conn.Auth.Proto314, conn.Auth.SecretKey, claims, conn.EncodedBuf[:]); err != nil {
			zap.L().Error("Ack token create failed", zap.String("flow", tcpPacket.L4FlowHash()), zap.Error(err))
			conn.Context.Counters().CounterError(appAckCounterFromError(err), err) //nolint
		}
	}

	// Packets with no authorization are processed as external services based on the ACLS
	if err = tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil || (err == nil && tcpPacket.IsEmptyTCPPayload()) {

		if _, err := d.puFromContextID.Get(conn.Context.ID()); err != nil {
			// PU has been deleted. Ignore these packets
			return nil, conn.Context.Counters().CounterError(counters.ErrInvalidSynAck, fmt.Errorf("Pu with ID delete %s", conn.Context.ID()))
		}

		flowHash := tcpPacket.SourceAddress().String() + ":" + strconv.Itoa(int(tcpPacket.SourcePort()))
		if plci, plerr := context.RetrieveCachedExternalFlowPolicy(flowHash); plerr == nil {
			plc := plci.(*policyPair)
			d.releaseExternalFlow(context, plc.report, plc.packet, tcpPacket)
			conn.Context.Counters().IncrementCounter(counters.ErrSynAckFromExtNetAccept)
			return nil, nil
		}

		// Never seen this IP before, let's parse them.
		report, pkt, perr := context.ApplicationACLPolicyFromAddr(tcpPacket.SourceAddress(), tcpPacket.SourcePort(), tcpPacket.IPProto())

		// Ping packet from an external network.
		if conn.PingEnabled() {
			err := d.processPingNetSynAckPacket(context, conn, tcpPacket, 0, pkt, nil, true)
			if err != nil && err != errDropPingNetSynAck {
				zap.L().Error("unable to process ping network synack (externalnetwork)", zap.Error(err))
			}
			return nil, err
		}

		if perr != nil || pkt.Action.Rejected() {
			d.reportReverseExternalServiceFlow(context, report, pkt, true, tcpPacket)
			return nil, conn.Context.Counters().CounterError(counters.ErrSynAckFromExtNetReject, fmt.Errorf("ErrSynAckFromExtNetReject"))
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
		d.releaseExternalFlow(context, report, pkt, tcpPacket)
		conn.Context.Counters().IncrementCounter(counters.ErrSynAckFromExtNetAccept)

		return nil, nil
	}

	// This is a corner condition. We are receiving a SynAck packet and we are in
	// a state that indicates that we have already processed one. This means that
	// our ack packet was lost. We need to revert conntrack in this case and get
	// back into the picture.
	if conn.GetState() != connection.TCPSynSend {
		// Revert the connmarks - dealing with retransmissions
		if cerr := d.conntrack.UpdateApplicationFlowMark(
			tcpPacket.DestinationAddress(),
			tcpPacket.SourceAddress(),
			tcpPacket.IPProto(),
			tcpPacket.DestPort(),
			tcpPacket.SourcePort(),
			uint32(1), // We cannot put it back to zero. We need something other value.
		); cerr != nil {
			zap.L().Debug("Failed to update conntrack table for flow after synack packet",
				zap.String("app-conn", tcpPacket.L4ReverseFlowHash()),
				zap.String("state", fmt.Sprintf("%d", conn.GetState())),
				zap.Error(err),
			)
		}

		conn.SetState(connection.TCPSynAckReceived)
	}

	if !d.mutualAuthorization {
		allowPkt()
		return nil, nil
	}

	token := tcpPacket.ReadTCPData()
	if err = d.serverIdentityAllowed(context, token, tcpPacket, conn); err == nil {
		processAfterVerdict := func() {
			createAckToken()
		}
		allowPkt()
		return processAfterVerdict, nil
	}

	return nil, err
}

func (d *Datapath) serverIdentityAllowed(context *pucontext.PUContext, token []byte, tcpPacket *packet.Packet, conn *connection.TCPConnection) error {

	claims := &conn.Auth.ConnectionClaims
	secretKey, claimsHeader, controller, remoteNonce, remoteContextID, proto314, err := d.tokenAccessor.ParsePacketToken(conn.Auth.LocalDatapathPrivateKey, token, conn.Secrets, claims, true)

	if err != nil {
		zap.L().Error("Syn/Ack token parse error", zap.String("flow", tcpPacket.L4FlowHash()), zap.Error(err))
		d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidToken, nil, nil, true)
		return context.Counters().CounterError(netSynAckCounterFromError(err), err)
	}

	conn.Auth.SecretKey = secretKey
	conn.Auth.RemoteNonce = remoteNonce
	conn.Auth.RemoteContextID = remoteContextID
	conn.Auth.Proto314 = proto314

	if controller != nil && ((conn.PingEnabled()) || (!controller.SameController)) {
		conn.DestinationController = controller.Controller
	}

	// Add the port as a label with an @ prefix. These labels are invalid otherwise
	// If all policies are restricted by port numbers this will allow port-specific policies
	tags := claims.T.Copy()
	tags.AppendKeyValue(constants.PortNumberLabelString, constants.TCPProtoString+"/"+strconv.Itoa(int(tcpPacket.SourcePort())))

	// Add the controller to the claims
	if controller != nil && len(controller.Controller) > 0 {
		tags.AppendKeyValue(constants.ControllerLabelString, controller.Controller)
	}

	report, pkt := context.SearchTxtRules(tags, !d.mutualAuthorization)

	// Ping packet from remote enforcer.
	if claimsHeader != nil {
		if claimsHeader.Ping() && claims.P != nil {
			payloadSize := len(token)
			err := d.processPingNetSynAckPacket(context, conn, tcpPacket, payloadSize, pkt, claims, false)
			if err != nil && err != errDropPingNetSynAck {
				zap.L().Error("unable to process ping network synack", zap.Error(err))
			}
			return err
		}
	}

	// Report and release traffic belonging to the same pu
	if conn.Auth.RemoteContextID == context.ManagementID() {
		conn.SetState(connection.TCPData)
		conn.SetLoopbackConnection(true)
		d.reportAcceptedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID(), context, nil, nil, true)
		d.releaseUnmonitoredFlow(tcpPacket)
		return nil
	}

	if pkt.Action.Rejected() {
		d.reportRejectedFlow(tcpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID(), context, collector.PolicyDrop, report, pkt, true)
		return context.Counters().CounterError(counters.ErrSynAckRejected, fmt.Errorf("ErrSynAckRejected"))
	}

	return nil
}

// processNetworkAckPacket processes an Ack packet arriving from the network
func (d *Datapath) processNetworkAckPacket(context *pucontext.PUContext, conn *connection.TCPConnection, tcpPacket *packet.Packet) error {

	var err error

	if conn.GetState() == connection.TCPData || conn.GetState() == connection.TCPAckSend {

		// This rule is required as network packets are being duplicated by the middle box in google. Our ack packets contain payload and that will be sent to the tcp stack,
		// if we don't drop them here.
		if err := tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err == nil {
			return conn.Context.Counters().CounterError(counters.ErrDuplicateAckDrop, fmt.Errorf("ErrDuplicateAckDrop"))
		}

		conn.ResetTimer(waitBeforeRemovingConn)
		tcpPacket.SetConnmark = true
		return nil
	}

	if conn.IsLoopbackConnection() {
		conn.SetState(connection.TCPData)
		d.releaseUnmonitoredFlow(tcpPacket)
		return nil
	}

	// Validate that the source/destination nonse matches. The signature has validated both directions
	if conn.GetState() == connection.TCPSynAckSend || conn.GetState() == connection.TCPSynReceived {

		if err := tcpPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen); err != nil {
			return conn.Context.Counters().CounterError(counters.ErrAckTCPNoTCPAuthOption, fmt.Errorf("ErrAckTCPNoTCPAuthOption"))
		}

		if err = d.tokenAccessor.ParseAckToken(conn.Auth.Proto314, conn.Auth.SecretKey, conn.Auth.Nonce[:], tcpPacket.ReadTCPData(), &conn.Auth.ConnectionClaims); err != nil {
			zap.L().Error("Ack Packet dropped because signature validation failed", zap.String("flow", tcpPacket.L4FlowHash()), zap.Error(err))
			d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidToken, nil, nil, false)
			return conn.Context.Counters().CounterError(netAckCounterFromError(err), err)
		}

		tcpPacket.TCPDataDetach(enforcerconstants.TCPAuthenticationOptionBaseLen)

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

		if err := d.ignoreFlow(tcpPacket); err != nil {
			zap.L().Error("Failed to ignore flow", zap.Error(err))
		}
		conn.Context.Counters().IncrementCounter(counters.ErrConnectionsProcessed)
		// Accept the packet
		return nil
	}

	if conn.GetState() == connection.UnknownState {
		// Check if the destination is in the external servicess approved cache
		// and if yes, allow the packet to go and release the flow.
		_, plcy, perr := context.NetworkACLPolicy(tcpPacket)

		// Ignore FIN packets. Let them go through.
		if tcpPacket.GetTCPFlags()&packet.TCPFinMask != 0 {
			conn.Context.Counters().IncrementCounter(counters.ErrIgnoreFin)
			return nil
		}

		if perr != nil {
			conn.Context.Counters().CounterError(counters.ErrAckInUnknownState, nil) //nolint
			zap.L().Debug("converting to rst network",
				zap.String("SourceIP", tcpPacket.SourceAddress().String()),
				zap.String("DestinationIP", tcpPacket.DestinationAddress().String()),
				zap.Int("SourcePort", int(tcpPacket.SourcePort())),
				zap.Int("DestinationPort", int(tcpPacket.DestPort())),
				zap.String("Flags", packet.TCPFlagsToStr(tcpPacket.GetTCPFlags())),
			)
			tcpPacket.ConvertToRst()

			tcpPacket.SetConnmark = true
			return nil
		}

		if plcy.Action.Rejected() {
			return conn.Context.Counters().CounterError(counters.ErrAckFromExtNetReject, fmt.Errorf("ErrAckFromExtNetReject"))
		}

		if err := d.ignoreFlow(tcpPacket); err != nil {
			zap.L().Error("Failed to ignore flow", zap.Error(err))
		}

		tcpPacket.SetConnmark = true

		conn.Context.Counters().IncrementCounter(counters.ErrAckFromExtNetAccept)
		return nil
	}

	hash := tcpPacket.L4FlowHash()

	// Everything else is dropped - ACK received in the Syn state without a SynAck
	zap.L().Debug("Invalid state reached",
		zap.String("state", fmt.Sprintf("%d", conn.GetState())),
		zap.String("context", context.ManagementID()),
		zap.String("net-conn", hash),
	)

	return conn.Context.Counters().CounterError(counters.ErrInvalidNetAckState, fmt.Errorf("ErrInvalidNetAckState"))
}

// appSynRetrieveState retrieves state for the the application Syn packet.
// It creates a new connection by default
func (d *Datapath) appSynRetrieveState(p *packet.Packet) (*connection.TCPConnection, error) {
	var err error
	var context *pucontext.PUContext

	// If PU context doesn't exist for this syn, return error.
	if context, err = d.contextFromIP(true, p.Mark, p.SourcePort(), packet.IPProtocolTCP); err != nil {
		return nil, counters.CounterError(counters.ErrSynUnexpectedPacket, err)
	}

	// check if app syn has been seen?
	if conn, exists := d.cacheGet(d.tcpClient, p.L4FlowHash()); exists {
		if !conn.GetMarkForDeletion() && conn.GetInitialSequenceNumber() == p.TCPSequenceNumber() {
			// return this connection only if we are not deleting this
			// this is marked only when we see a FINACK for this l4flowhash
			// this should not have happened for a connection while we are processing a appSyn for this connection
			// The addorupdate for this cache will happen outside in processtcppacket
			return conn, nil
		} else { //nolint
			//stale app syn. We remove from the cache
			d.cacheRemove(d.tcpClient, p.L4FlowHash())
		}
	}
	return connection.NewTCPConnection(context, p), nil
}

// appSynAckRetrieveState retrieves the state for application syn/ack packet.
func (d *Datapath) appSynAckRetrieveState(p *packet.Packet) (*connection.TCPConnection, error) {
	hash := p.L4ReverseFlowHash()

	// We must have seen a network syn.
	if conn, exists := d.cacheGet(d.tcpServer, hash); exists {
		return conn, nil
	}

	return nil, counters.CounterError(counters.ErrNetSynNotSeen, errors.New("Network Syn not seen"))
}

// appRetrieveState retrieves the state for the rest of the application packets. It
// returns an error if it cannot find the state
func (d *Datapath) appRetrieveState(p *packet.Packet) (*connection.TCPConnection, error) {

	// Is this ack generated from a PU, a tcp client.
	if conn, exists := d.cacheGet(d.tcpClient, p.L4FlowHash()); exists {
		return conn, nil
	}

	// is this ack generated from a PU, a tcp server.
	if conn, exists := d.cacheGet(d.tcpServer, p.L4ReverseFlowHash()); exists {
		return conn, nil
	}

	counters.CounterError(counters.ErrNoConnFound, nil) //nolint

	zap.L().Debug("Application ACK Packet received with no state",
		zap.String("flow", p.L4FlowHash()),
		zap.String("Flags", packet.TCPFlagsToStr(p.GetTCPFlags())))

	if p.GetTCPFlags()&packet.TCPSynAckMask == packet.TCPAckMask {
		// Let's try if its an existing connection
		context, err := d.contextFromIP(true, p.Mark, p.SourcePort(), packet.IPProtocolTCP)
		if err != nil {
			return nil, errors.New("No context in app processing")
		}
		conn := connection.NewTCPConnection(context, p)
		conn.SetState(connection.UnknownState)
		return conn, nil
	}

	if p.GetTCPFlags()&packet.TCPRstMask != 0 && p.GetTCPFlags()&packet.TCPAckMask == 0 {
		return nil, errRstPacket
	}

	return nil, errNoConnection
}

// netSynRetrieveState retrieves the state for the Syn packets on the network.
// Obviously if no state is found, it generates a new connection record.
func (d *Datapath) netSynRetrieveState(p *packet.Packet) (*connection.TCPConnection, error) {

	var conn *connection.TCPConnection
	var context *pucontext.PUContext
	var err error

	if context, err = d.contextFromIP(false, p.Mark, p.DestPort(), packet.IPProtocolTCP); err != nil {
		return nil, counters.CounterError(counters.ErrInvalidNetSynState, err)
	}

	if conn, exists := d.cacheGet(d.tcpServer, p.L4FlowHash()); exists {
		if !conn.GetMarkForDeletion() && conn.GetInitialSequenceNumber() == p.TCPSequenceNumber() {
			// Only if we havent seen FINACK on this connection
			return conn, nil
		} else { //nolint
			// remove stale net syn entry
			d.cacheRemove(d.tcpServer, p.L4FlowHash())
		}
	}

	conn = connection.NewTCPConnection(context, p)

	conn.Secrets, conn.Auth.LocalDatapathPrivateKey, conn.Auth.LocalDatapathPublicKeyV1, conn.Auth.LocalDatapathPublicKeySignV1, conn.Auth.LocalDatapathPublicKeyV2, conn.Auth.LocalDatapathPublicKeySignV2 = context.GetSecrets()
	return conn, nil
}

// netSynAckRetrieveState retrieves the state for SynAck packets at the network
// It relies on the source port cache for that
func (d *Datapath) netSynAckRetrieveState(p *packet.Packet) (*connection.TCPConnection, error) {

	// We must have seen App Syn
	if conn, exists := d.cacheGet(d.tcpClient, p.L4ReverseFlowHash()); exists {
		if conn.GetMarkForDeletion() {
			return nil, errOutOfOrderSynAck
		}
		return conn, nil
	}

	return nil, counters.CounterError(counters.ErrNonPUTraffic, errNonPUTraffic)
}

// netRetrieveState retrieves the state of a network connection. Use the flow caches for that
func (d *Datapath) netRetrieveState(p *packet.Packet) (*connection.TCPConnection, error) {
	// Is the ack received by a tcp client
	if conn, exists := d.cacheGet(d.tcpClient, p.L4ReverseFlowHash()); exists {
		if p.GetTCPFlags()&packet.TCPRstMask != 0 && p.GetTCPFlags()&packet.TCPAckMask == 0 {
			if !bytes.Equal(p.ReadTCPData(), rstIdentity) {
				conn.SetReportReason("reset")
			}
			return conn, errRstPacket
		}
		return conn, nil
	}

	// Is the ack received by a tcp server
	if conn, exists := d.cacheGet(d.tcpServer, p.L4FlowHash()); exists {
		return conn, nil
	}

	if p.GetTCPFlags()&packet.TCPSynAckMask == packet.TCPAckMask {
		// Let's try if its an existing connection
		context, cerr := d.contextFromIP(false, p.Mark, p.DestPort(), packet.IPProtocolTCP)
		if cerr != nil {
			return nil, cerr
		}
		conn := connection.NewTCPConnection(context, p)
		conn.SetState(connection.UnknownState)
		return conn, nil
	}

	if p.GetTCPFlags()&packet.TCPRstMask != 0 && p.GetTCPFlags()&packet.TCPAckMask == 0 {
		return nil, errRstPacket
	}

	return nil, errNoConnection
}

// releaseExternalFlow releases the flow and updates the conntrack table
func (d *Datapath) releaseExternalFlow(context *pucontext.PUContext, report *policy.FlowPolicy, action *policy.FlowPolicy, tcpPacket *packet.Packet) {

	d.cacheRemove(d.tcpClient, tcpPacket.L4ReverseFlowHash())

	if err := d.ignoreFlow(tcpPacket); err != nil {
		zap.L().Error("Failed to ignore flow", zap.Error(err))
	}

	tcpPacket.SetConnmark = true
	d.reportReverseExternalServiceFlow(context, report, action, true, tcpPacket)
}

// releaseUnmonitoredFlow releases the flow and updates the conntrack table
func (d *Datapath) releaseUnmonitoredFlow(tcpPacket *packet.Packet) {

	if err := d.ignoreFlow(tcpPacket); err != nil {
		zap.L().Error("Failed to ignore flow", zap.Error(err))
	}

	tcpPacket.SetConnmark = true
}
