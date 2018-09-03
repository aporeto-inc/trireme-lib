package nfqdatapath

// Go libraries
import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
)

// ProcessNetworkUDPPacket processes packets arriving from network and are destined to the application.
func (d *Datapath) ProcessNetworkUDPPacket(p *packet.Packet) (err error) {

	if d.packetLogs {
		zap.L().Debug("Processing network packet ",
			zap.String("flow", p.L4FlowHash()),
		)
		defer zap.L().Debug("Finished Processing network packet ",
			zap.String("flow", p.L4FlowHash()),
			zap.Error(err),
		)
	}

	var conn *connection.UDPConnection

	udpPacketType := p.GetUDPType()
	zap.L().Debug("Got packet of type:", zap.Reflect("Type", udpPacketType), zap.Reflect("Len", len(p.Buffer)))

	switch udpPacketType {
	case packet.UDPSynMask:
		conn, err = d.netSynUDPRetrieveState(p)
		if err != nil {
			if d.packetLogs {
				zap.L().Debug("Packet rejected",
					zap.String("flow", p.L4FlowHash()),
					zap.Error(err),
				)
			}
			return err
		}

	case packet.UDPSynAckMask:
		conn, err = d.netSynAckUDPRetrieveState(p)
		if err != nil {
			if d.packetLogs {
				zap.L().Debug("Syn ack Packet Rejected/ignored",
					zap.String("flow", p.L4FlowHash()),
				)
			}
			return err
		}

	case packet.UDPAckMask:
		conn, err = d.netUDPAckRetrieveState(p)
		if err != nil {
			if d.packetLogs {
				zap.L().Debug("Packet rejected",
					zap.String("flow", p.L4FlowHash()),
					zap.Error(err),
				)
			}
			return err
		}
	default:
		// Process packets that don't have the control header. These are data packets.
		conn, err = d.netUDPAckRetrieveState(p)
		if err != nil {
			if d.packetLogs {
				zap.L().Debug("No connection found for the flow, Dropping it",
					zap.String("flow", p.L4FlowHash()),
					zap.Error(err),
				)
			}
			return err
		}

		// Pass the packet to the service.
		if d.service != nil {
			if !d.service.PostProcessUDPNetPacket(p, nil, nil, conn.Context, conn) {
				p.Print(packet.PacketFailureService)
				return errors.New("post service processing failed for network packet")
			}
		}
		zap.L().Debug("Delivering packet to application")
		return nil
	}

	p.Print(packet.PacketStageIncoming)

	if d.service != nil {
		if !d.service.PreProcessUDPNetPacket(p, conn.Context, conn) {
			p.Print(packet.PacketFailureService)
			return errors.New("pre  processing failed for network packet")
		}
	}

	// handle handshake packets and do not deliver to application.
	err = d.processNetUDPPacket(p, conn.Context, conn)
	if err != nil {
		if d.packetLogs {
			zap.L().Debug("Rejecting packet ",
				zap.String("flow", p.L4FlowHash()),
				zap.Error(err),
			)
		}
		return fmt.Errorf("packet processing failed for network packet: %s", err)
	}
	// handshake packets are not to be delivered to application.
	return fmt.Errorf("Drop net hanshake packets (udp)")
}

func (d *Datapath) netSynUDPRetrieveState(p *packet.Packet) (*connection.UDPConnection, error) {

	// Retrieve the context from the packet information.
	context, err := d.contextFromIP(false, p.DestinationAddress.String(), p.Mark, p.DestinationPort, packet.IPProtocolUDP)
	if err != nil {
		return nil, err
	}

	// Check if a connection already exists for this flow. This can happen
	// in the case of retransmissions. If there is no connection, create
	// a new one.
	conn, cerr := d.udpNetOrigConnectionTracker.Get(p.L4FlowHash())
	if cerr != nil {
		return connection.NewUDPConnection(context, d.udpSocketWriter), nil
	}
	return conn.(*connection.UDPConnection), nil
}

func (d *Datapath) netSynAckUDPRetrieveState(p *packet.Packet) (*connection.UDPConnection, error) {

	conn, err := d.udpSourcePortConnectionCache.GetReset(p.SourcePortHash(packet.PacketTypeNetwork), 0)
	if err != nil {
		return nil, fmt.Errorf("No connection.Drop the syn ack packet")
	}

	return conn.(*connection.UDPConnection), nil
}

func (d *Datapath) netUDPAckRetrieveState(p *packet.Packet) (*connection.UDPConnection, error) {

	hash := p.L4FlowHash()
	conn, err := d.udpNetReplyConnectionTracker.GetReset(hash, 0)
	if err != nil {
		conn, err = d.udpNetOrigConnectionTracker.GetReset(hash, 0)
		if err != nil {
			return nil, fmt.Errorf("net state not found: %s", err)
		}
	}
	return conn.(*connection.UDPConnection), nil
}

// processNetUDPPacket processes a network UDP packet and dispatches it to different methods based on the flags.
// This applies only to control packets.
func (d *Datapath) processNetUDPPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {

	// Extra check, just in case the caller didn't provide a connection.
	if conn == nil {
		return fmt.Errorf("no connection provided")
	}

	udpPacketType := udpPacket.GetUDPType()
	// Update connection state in the internal state machine tracker
	switch udpPacketType {
	case packet.UDPSynMask:

		// Parse the packet for the identity information.
		action, claims, err := d.processNetworkUDPSynPacket(context, conn, udpPacket)
		if err != nil {
			return err
		}

		// Process the packet by any external services.
		if d.service != nil {
			if !d.service.PostProcessUDPNetPacket(udpPacket, action, claims, conn.Context, conn) {
				udpPacket.Print(packet.PacketFailureService)
				return fmt.Errorf("post service processing failed for network packet")
			}
		}

		// Send the return packet.
		if err = d.sendUDPSynAckPacket(udpPacket, context, conn); err != nil {
			return err
		}

		// Mark the state that we have transmitted a SynAck packet.
		conn.SetState(connection.UDPSynAckSent)

	case packet.UDPAckMask:

		// Retrieve the header and parse the signatures.
		action, claims, err := d.processNetworkUDPAckPacket(udpPacket, context, conn)
		if err != nil {
			zap.L().Error("Error during authorization", zap.Error(err))
			return err
		}

		// Process an external services.
		if d.service != nil {
			if !d.service.PostProcessUDPNetPacket(udpPacket, action, claims, conn.Context, conn) {
				udpPacket.Print(packet.PacketFailureService)
				return fmt.Errorf("post service processing failed for network packet")
			}
		}

		// Set the connection to
		conn.SetState(connection.UDPAckProcessed)

	case packet.UDPSynAckMask:

		// Process the synack header and claims of the other side.
		action, claims, err := d.processNetworkUDPSynAckPacket(udpPacket, context, conn)
		if err != nil {
			zap.L().Error("UDP Syn ack failed with", zap.Error(err))
			return err
		}

		if d.service != nil {
			if !d.service.PostProcessUDPNetPacket(udpPacket, action, claims, conn.Context, conn) {
				udpPacket.Print(packet.PacketFailureService)
				return fmt.Errorf("post service processing dropped the packet")
			}
		}

		// Send back the acknowledgement.
		err = d.sendUDPAckPacket(udpPacket, context, conn)
		if err != nil {
			zap.L().Error("Unable to send udp Syn ack failed", zap.Error(err))
			return err
		}
	}
	return nil
}

// ProcessApplicationUDPPacket processes packets arriving from an application and are destined to the network
func (d *Datapath) ProcessApplicationUDPPacket(p *packet.Packet) (err error) {

	if d.packetLogs {
		zap.L().Debug("Processing application UDP packet ",
			zap.String("flow", p.L4FlowHash()),
		)
		defer zap.L().Debug("Finished Processing UDP application packet ",
			zap.String("flow", p.L4FlowHash()),
			zap.Error(err),
		)
	}

	var conn *connection.UDPConnection
	conn, err = d.appUDPRetrieveState(p)
	if err != nil {
		zap.L().Debug("Connection not found", zap.Error(err))
		return fmt.Errorf("Received packet from unenforced process: %s", err)
	}

	switch conn.GetState() {
	case connection.UDPSynStart:
		// Queue the packet. We will send it after we authorize the session.
		if err = conn.QueuePackets(p); err != nil {
			return fmt.Errorf("Unable to queue packets:%s", err)
		}

		// Process the application packet.
		err = d.processApplicationUDPSynPacket(p, conn.Context, conn)
		if err != nil {
			return fmt.Errorf("Unable to send UDP Syn packet: %s", err)
		}

	case connection.UDPAckProcessed:
		// check for encryption and do the needful.
		if d.service != nil {
			// PostProcessServiceInterface
			if !d.service.PostProcessUDPAppPacket(p, nil, conn.Context, conn) {
				p.Print(packet.PacketFailureService)
				return errors.New("Encryption failed for application packet")
			}
		}
		// Set verdict to 1.
		zap.L().Debug("Ack Processed, write on the app socket")
		return nil

	default:
		zap.L().Info("Packets are being queueed", zap.String("flow", p.L4FlowHash()))
		if err = conn.QueuePackets(p); err != nil {
			return fmt.Errorf("Unable to queue packets:%s", err)
		}
	}
	// if not in the above two states, packets are queued. NFQ can drop them, as they are already
	// in connection packet queue.
	zap.L().Debug("Dropping packet by setting verdict to 0", zap.String("flow", p.L4FlowHash()))
	return fmt.Errorf("Packets cloned. Dropping the original packet")
}

func (d *Datapath) appUDPRetrieveState(p *packet.Packet) (*connection.UDPConnection, error) {

	hash := p.L4FlowHash()

	if conn, err := d.udpAppReplyConnectionTracker.GetReset(hash, 0); err == nil {
		return conn.(*connection.UDPConnection), nil
	}

	if conn, err := d.udpAppOrigConnectionTracker.GetReset(hash, 0); err == nil {
		return conn.(*connection.UDPConnection), nil
	}

	context, err := d.contextFromIP(true, p.SourceAddress.String(), p.Mark, p.SourcePort, packet.IPProtocolUDP)
	if err != nil {
		return nil, errors.New("No context in app processing")
	}

	return connection.NewUDPConnection(context, d.udpSocketWriter), nil
}

// processApplicationUDPSynPacket processes a single Syn Packet
func (d *Datapath) processApplicationUDPSynPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {

	if !addressMatch(udpPacket.DestinationAddress, context.UDPNetworks()) {
		d.reportUDPExternalFlow(udpPacket, context, true, nil, nil)
		return errors.New("No target found")
	}
	// do some pre processing.
	if d.service != nil {
		// PreProcessServiceInterface
		if !d.service.PreProcessUDPAppPacket(udpPacket, conn.Context, conn, packet.UDPSynMask) {
			udpPacket.Print(packet.PacketFailureService)
			return errors.New("pre service processing failed for UDP application packet")
		}
	}

	udpOptions := d.CreateUDPAuthMarker(packet.UDPSynMask)
	udpData, err := d.tokenAccessor.CreateSynPacketToken(context, &conn.Auth)

	if err != nil {
		return err
	}

	newPacket, err := d.clonePacketHeaders(udpPacket)
	if err != nil {
		return fmt.Errorf("Unable to clone packet: %s", err)
	}
	// Attach the UDP data and token
	newPacket.UDPTokenAttach(udpOptions, udpData)

	// send packet
	// err = d.udpSocketWriter.WriteSocket(newPacket.Buffer)
	err = d.writeWithRetransmit(newPacket.Buffer, conn.SynChannel())
	if err != nil {
		zap.L().Error("Unable to send syn token on raw socket", zap.Error(err))
		return errors.New("unable to transmit syn packet")
	}

	// Set the state indicating that we send out a Syn packet
	conn.SetState(connection.UDPSynSend)

	// Poplate the caches to track the connection
	hash := udpPacket.L4FlowHash()
	d.udpAppOrigConnectionTracker.AddOrUpdate(hash, conn)
	d.udpSourcePortConnectionCache.AddOrUpdate(newPacket.SourcePortHash(packet.PacketTypeApplication), conn)
	d.udpNatConnectionTracker.AddOrUpdate(newPacket.SourcePortHash(packet.PacketTypeApplication), newPacket.SourcePortHash(packet.PacketTypeNetwork))
	// Attach the tags to the packet and accept the packet

	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessUDPAppPacket(newPacket, nil, conn.Context, conn) {
			newPacket.Print(packet.PacketFailureService)
			return errors.New("post service processing failed for application packet")
		}
	}

	return nil

}

func (d *Datapath) writeWithRetransmit(buffer []byte, stop chan bool) error {

	localBuffer := make([]byte, len(buffer))
	copy(localBuffer, buffer)

	if err := d.udpSocketWriter.WriteSocket(localBuffer); err != nil {
		zap.L().Error("Failed to write control packet to socket", zap.Error(err))
		return err
	}

	go func() {
		for retries := 0; retries < 3; retries++ {
			delay := time.Millisecond * time.Duration((200 * (retries + 1)))
			select {
			case <-stop:
				return
			case <-time.After(delay):
				if err := d.udpSocketWriter.WriteSocket(localBuffer); err != nil {
					zap.L().Error("Failed to write control packet to socket", zap.Error(err))
				}
			}
		}
	}()
	return nil
}

func (d *Datapath) clonePacketHeaders(p *packet.Packet) (*packet.Packet, error) {
	// copy the ip and udp headers.
	newPacket := make([]byte, packet.UDPDataPos)
	p.FixupIPHdrOnDataModify(p.IPTotalLength, packet.UDPDataPos)
	_ = copy(newPacket, p.Buffer[:packet.UDPDataPos])

	return packet.New(packet.PacketTypeApplication, newPacket, p.Mark, true)
}

// CreateUDPAuthMarker creates a UDP auth marker.
func (d *Datapath) CreateUDPAuthMarker(packetType uint8) []byte {

	// Every UDP control packet has a 20 byte packet signature. The
	// first 2 bytes represent the following control information.
	// Byte 0 : Bits 0,1 are reserved fields.
	//          Bits 2,3,4 represent version information.
	//          Bits 5, 6 represent udp packet type,
	//          Bit 7 represents encryption. (currently unused).
	// Byte 1: reserved for future use.
	// Bytes [2:20]: Packet signature.

	marker := make([]byte, packet.UDPSignatureLen)
	// ignore version info as of now.
	marker[0] |= packetType // byte 0
	marker[1] = 0           // byte 1
	// byte 2 - 19
	copy(marker[2:], []byte(packet.UDPAuthMarker))

	return marker
}

// processApplicationSynAckPacket processes a UDP SynAck packet
func (d *Datapath) sendUDPSynAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {

	// check for service and configure encryption based on
	// policy that was resolved on network syn.
	if d.service != nil {
		// PreProcessServiceInterface
		if !d.service.PreProcessUDPAppPacket(udpPacket, context, conn, packet.UDPSynAckMask) {
			udpPacket.Print(packet.PacketFailureService)
			return errors.New("pre service processing failed for application packet")
		}
	}

	// Create UDP Option
	udpOptions := d.CreateUDPAuthMarker(packet.UDPSynAckMask)

	udpData, err := d.tokenAccessor.CreateSynAckPacketToken(context, &conn.Auth)
	if err != nil {
		return err
	}

	udpPacket.CreateReverseFlowPacket(udpPacket.SourceAddress, udpPacket.SourcePort)

	// Attach the UDP data and token
	udpPacket.UDPTokenAttach(udpOptions, udpData)

	// Setup ConnMark for encryption.
	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessUDPAppPacket(udpPacket, nil, context, conn) {
			udpPacket.Print(packet.PacketFailureService)
			return errors.New("post service processing failed for application packet")
		}
	}

	// If we have already a backgroun re-transmit session, stop it at this point. We will
	// start from the beginning.
	if conn.GetState() == connection.UDPSynAckSent {
		conn.SynAckStop()
	}

	// Only start the retransmission timer once. Not on every packet.
	if err := d.writeWithRetransmit(udpPacket.Buffer, conn.SynAckChannel()); err != nil {
		zap.L().Debug("Unable to send synack token on raw socket", zap.Error(err))
		return err
	}

	// Set the state for future reference
	conn.SetState(connection.UDPSynAckSent)

	return nil
}

func (d *Datapath) sendUDPAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {

	// Create UDP Option
	zap.L().Debug("Sending UDP Ack packet", zap.String("flow", udpPacket.L4ReverseFlowHash()))
	udpOptions := d.CreateUDPAuthMarker(packet.UDPAckMask)

	udpData, err := d.tokenAccessor.CreateAckPacketToken(context, &conn.Auth)

	if err != nil {
		return err
	}

	srcPortHash, err := d.udpNatConnectionTracker.GetReset(udpPacket.SourcePortHash(packet.PacketTypeNetwork), 0)
	if err != nil {
		return fmt.Errorf("error getting actual destination")
	}

	destIPPort := srcPortHash.(string)
	destIP := strings.Split(destIPPort, ":")[0]
	destPort, err := (strconv.Atoi(strings.Split(destIPPort, ":")[1]))
	if err != nil {
		return fmt.Errorf("Unable to get dest port from cache")
	}

	udpPacket.CreateReverseFlowPacket(net.ParseIP(destIP), uint16(destPort))

	// Attach the UDP data and token
	udpPacket.UDPTokenAttach(udpOptions, udpData)

	// send packet
	err = d.udpSocketWriter.WriteSocket(udpPacket.Buffer)
	if err != nil {
		zap.L().Debug("Unable to send ack token on raw socket", zap.Error(err))
	}

	conn.SetState(connection.UDPAckProcessed)

	if !conn.ServiceConnection {
		zap.L().Debug("Plumbing the conntrack (app) rule for flow", zap.String("flow", udpPacket.L4FlowHash()))

		if err = d.conntrackHdl.ConntrackTableUpdateMark(
			destIP,
			udpPacket.SourceAddress.String(),
			udpPacket.IPProto,
			uint16(destPort),
			udpPacket.SourcePort,
			constants.DefaultConnMark,
		); err != nil {
			zap.L().Error("Failed to update conntrack table for flow",
				zap.String("context", string(conn.Auth.LocalContext)),
				zap.String("app-conn", udpPacket.L4ReverseFlowHash()),
				zap.String("state", fmt.Sprintf("%d", conn.GetState())),
				zap.Error(err),
			)
		}
	}

	// Transmit Queued Packets.
	for udpPacket := conn.ReadPacket(); udpPacket != nil; udpPacket = conn.ReadPacket() {
		// check for Encryption.
		if d.service != nil {
			// PostProcessServiceInterface
			if !d.service.PostProcessUDPAppPacket(udpPacket, nil, conn.Context, conn) {
				udpPacket.Print(packet.PacketFailureService)
				return errors.New("Encryption failed for queued application packet")
			}
		}
		zap.L().Debug("Transmitting Queued UDP packets")
		err = d.udpSocketWriter.WriteSocket(udpPacket.Buffer)
		if err != nil {
			zap.L().Error("Unable to transmit Queued UDP packets", zap.Error(err))
		}
	}

	return err
}

// processNetworkUDPSynPacket processes a syn packet arriving from the network
func (d *Datapath) processNetworkUDPSynPacket(context *pucontext.PUContext, conn *connection.UDPConnection, udpPacket *packet.Packet) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	claims, err = d.tokenAccessor.ParsePacketToken(&conn.Auth, udpPacket.ReadUDPToken())
	if err != nil {
		d.reportUDPRejectedFlow(udpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidToken, nil, nil)
		return nil, nil, fmt.Errorf("UDP Syn packet dropped because of invalid token: %s", err)
	}

	// if there are no claims we must drop the connection and we drop the Syn
	// packet. The source will retry but we have no state to maintain here.
	if claims == nil {
		d.reportUDPRejectedFlow(udpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidToken, nil, nil)
		return nil, nil, errors.New("UDP Syn packet dropped because of no claims")
	}

	// Why is this required. Take a look.
	txLabel, _ := claims.T.Get(enforcerconstants.TransmitterLabel)

	// Add the port as a label with an @ prefix. These labels are invalid otherwise
	// If all policies are restricted by port numbers this will allow port-specific policies
	claims.T.AppendKeyValue(enforcerconstants.PortNumberLabelString, strconv.Itoa(int(udpPacket.DestinationPort)))

	report, pkt := context.SearchRcvRules(claims.T)
	if pkt.Action.Rejected() {
		d.reportUDPRejectedFlow(udpPacket, conn, txLabel, context.ManagementID(), context, collector.PolicyDrop, report, pkt)
		return nil, nil, fmt.Errorf("connection rejected because of policy: %s", claims.T.String())
	}

	hash := udpPacket.L4FlowHash()

	// conntrack
	d.udpNetOrigConnectionTracker.AddOrUpdate(hash, conn)
	d.udpAppReplyConnectionTracker.AddOrUpdate(udpPacket.L4ReverseFlowHash(), conn)

	// Record actions
	conn.ReportFlowPolicy = report
	conn.PacketFlowPolicy = pkt

	return pkt, claims, nil
}

func (d *Datapath) processNetworkUDPSynAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	conn.SynStop()

	// Packets that have authorization information go through the auth path
	// Decode the JWT token using the context key
	claims, err = d.tokenAccessor.ParsePacketToken(&conn.Auth, udpPacket.ReadUDPToken())
	if err != nil {
		d.reportUDPRejectedFlow(udpPacket, nil, collector.DefaultEndPoint, context.ManagementID(), context, collector.MissingToken, nil, nil)
		return nil, nil, fmt.Errorf("SynAck packet dropped because of bad claims: %s", err)
	}

	if claims == nil {
		d.reportUDPRejectedFlow(udpPacket, nil, collector.DefaultEndPoint, context.ManagementID(), context, collector.MissingToken, nil, nil)
		return nil, nil, errors.New("SynAck packet dropped because of no claims")
	}

	report, pkt := context.SearchTxtRules(claims.T, !d.mutualAuthorization)
	if pkt.Action.Rejected() {
		d.reportUDPRejectedFlow(udpPacket, conn, context.ManagementID(), conn.Auth.RemoteContextID, context, collector.PolicyDrop, report, pkt)
		return nil, nil, fmt.Errorf("dropping because of reject rule on transmitter: %s", claims.T.String())
	}

	conn.SetState(connection.UDPSynAckReceived)
	// conntrack
	d.udpNetReplyConnectionTracker.AddOrUpdate(udpPacket.L4FlowHash(), conn)

	return pkt, claims, nil
}

func (d *Datapath) processNetworkUDPAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	conn.SynAckStop()

	_, err = d.tokenAccessor.ParseAckToken(&conn.Auth, udpPacket.ReadUDPToken())
	if err != nil {
		d.reportUDPRejectedFlow(udpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID(), context, collector.PolicyDrop, conn.ReportFlowPolicy, conn.PacketFlowPolicy)
		return nil, nil, fmt.Errorf("ack packet dropped because signature validation failed: %s", err)
	}

	conn.SetState(connection.UDPAckReceived)

	if !conn.ServiceConnection {
		zap.L().Debug("Plumb conntrack rule for flow:", zap.String("flow", udpPacket.L4FlowHash()))
		// Plumb connmark rule here.
		if err := d.conntrackHdl.ConntrackTableUpdateMark(
			udpPacket.DestinationAddress.String(),
			udpPacket.SourceAddress.String(),
			udpPacket.IPProto,
			udpPacket.DestinationPort,
			udpPacket.SourcePort,
			constants.DefaultConnMark,
		); err != nil {
			zap.L().Error("Failed to update conntrack table after ack packet")
		}
	}

	d.reportUDPAcceptedFlow(udpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID(), context, conn.ReportFlowPolicy, conn.PacketFlowPolicy)

	return nil, nil, nil
}
