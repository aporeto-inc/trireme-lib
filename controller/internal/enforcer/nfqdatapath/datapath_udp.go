package nfqdatapath

// Go libraries
import (
	"errors"
	"fmt"
	"strconv"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/controller/constants"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/constants"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/connection"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/packet"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/pucontext"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/tokens"
)

const (
	// UDPAuthMarker is marker for UDP. Change it later.
	UDPAuthMarker = "n30njxq7bmiwr6dtxqq"
	// UDPAuthMarkerLen is the length of UDP marker.
	UDPAuthMarkerLen = 19
)

// ProcessNetworkUDPPacket processes packets arriving from network and are destined to the application
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

	zap.L().Debug("Varks: Recieved packet from UDP peer?", zap.Reflect("packet", p), zap.Reflect("Length", len(p.Buffer)), zap.String("flow", p.L4FlowHash()))
	fmt.Println("UDP marker recieved is", p.Buffer[28:48])
	// Idealy all packets from network should only be auth packets, other packets will go to application
	// once connmark is set.
	var conn *connection.UDPConnection
	udpPacketType := p.GetUDPType()

	zap.L().Debug("Varks: Packet Type is:", zap.Reflect("udptype", udpPacketType))
	switch udpPacketType & packet.UDPSynAckMask {
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

		if conn == nil {
			zap.L().Debug("Conn should never be nil")
			return fmt.Errorf("Unable to create new connection")
		}
		conn.SetState(connection.UDPSynReceived)

	case packet.UDPSynAckMask:
		conn, err = d.netSynAckUDPRetrieveState(p)
		if err != nil {
			if d.packetLogs {
				zap.L().Debug("Packet Rejected",
					zap.String("flow", p.L4FlowHash()),
				)
			}
			// flush the packetQueue on errors.
			if conn != nil {
				zap.L().Debug("Dropping packets ")
				conn.DropPackets()
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
		// Decrypt the packet and deliver to the application.
		zap.L().Debug("Not an aporeto handshake packet, Check for encryption", zap.String("flow", p.L4FlowHash()))
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

		// decrypt the packet
		if d.service != nil {
			if !d.service.PostProcessUDPNetPacket(p, nil, nil, conn.Context, conn) {
				p.Print(packet.PacketFailureService)
				return errors.New("post service processing failed for network packet")
			}
		}

		// deliver to the application.
		return d.udpSocketNetworkWriter.WriteSocket(p.Buffer)

	}

	// p.Print(packet.PacketStageIncoming)

	if d.service != nil {
		if !d.service.PreProcessUDPNetPacket(p, conn.Context, conn) {
			//	p.Print(packet.PacketFailureService)
			return errors.New("pre service processing failed for network packet")
		}
	}

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
	// check for encryption and do it later on.
	// capture the encrypt action when policy is being resolved - netsyn/netsynack
	// in connection object and encrypt later on.

	return nil
}

func (d *Datapath) netSynUDPRetrieveState(p *packet.Packet) (*connection.UDPConnection, error) {

	context, err := d.contextFromIP(false, p.DestinationAddress.String(), p.Mark, p.DestinationPort)
	if err != nil {
		zap.L().Debug("Recieved Packets from unenforcerd process")
		return nil, err
	}

	// caution is this required
	// if conn, err := d.netOrigConnectionTracker.GetReset(p.L4FlowHash(), 0); err == nil {
	// 	return conn.(*connection.UDPConnection), nil
	// }

	return connection.NewUDPConnection(context, d.udpSocketWriter), nil
}

func (d *Datapath) netSynAckUDPRetrieveState(p *packet.Packet) (*connection.UDPConnection, error) {

	conn, err := d.udpSourcePortConnectionCache.GetReset(p.SourcePortHash(packet.PacketTypeNetwork), 0)
	if err != nil {
		if d.packetLogs {
			zap.L().Debug("No connection for SynAck packet ",
				zap.String("flow", p.L4FlowHash()),
			)
		}
		return nil, fmt.Errorf("no synack connection: %s", err)
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

// processNetUDPPacket processes a network UDP packet and dispatches it to different methods based on the flags
func (d *Datapath) processNetUDPPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {

	if conn == nil {
		return nil
	}

	udpPacketType := udpPacket.GetUDPType()
	// Update connection state in the internal state machine tracker
	switch udpPacketType & packet.UDPSynAckMask {

	case packet.UDPSynMask:
		action, claims, err := d.processNetworkUDPSynPacket(context, conn, udpPacket)
		if err != nil {
			return err
		}

		if d.service != nil {
			if !d.service.PostProcessUDPNetPacket(udpPacket, action, claims, conn.Context, conn) {
				udpPacket.Print(packet.PacketFailureService)
				return errors.New("post service processing failed for network packet")
			}
		}
		// setup Encryption based on action and claims.
		err = d.sendUDPSynAckPacket(udpPacket, context, conn)
		if err != nil {
			return err
		}

	case packet.UDPAckMask:
		action, claims, err := d.processNetworkUDPAckPacket(udpPacket, context, conn)
		if err != nil {
			zap.L().Error("Error during authorization", zap.Error(err))
			return err
		}
		// ack is processed, mark connmark rule and let other packets go through.
		if d.service != nil {
			if !d.service.PostProcessUDPNetPacket(udpPacket, action, claims, conn.Context, conn) {
				udpPacket.Print(packet.PacketFailureService)
				return errors.New("post service processing failed for network packet")
			}
		}
		return err

	case packet.UDPSynAckMask:
		action, claims, err := d.processNetworkUDPSynAckPacket(udpPacket, context, conn)
		if err != nil {
			zap.L().Error("UDP Syn ack failed with", zap.Error(err))
			return err
		}

		if d.service != nil {
			if !d.service.PostProcessUDPNetPacket(udpPacket, action, claims, conn.Context, conn) {
				udpPacket.Print(packet.PacketFailureService)
				return errors.New("post service processing failed for network packet")
			}
		}

		err = d.sendUDPAckPacket(udpPacket, context, conn)
		if err != nil {
			zap.L().Error("Unable to send udp Syn ack failed", zap.Error(err))
			return err
		}
	}
	// drop the packet, not authorized ?
	zap.L().Debug("Net: Recieved a flow which is not yet authorized")
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

	zap.L().Debug("Processing application UDP packet", zap.Reflect("length", len(p.Buffer)), zap.String("flow", p.L4FlowHash()))
	var conn *connection.UDPConnection
	conn, err = d.appUDPRetrieveState(p)
	if err != nil {
		return fmt.Errorf("Recieved packet from unenforced process: %s", err)
	}

	// queue packets if connection is still unauthorized.
	if conn.GetState() != connection.UDPAckProcessed {
		zap.L().Debug("Varks: Packets are queued")
		conn.QueuePackets(p)
	}

	switch conn.GetState() {

	case connection.UDPSynSend:
		// connection not authorized yet. queue the packets and start handshake.
		zap.L().Debug("Varks: Sending out Application UDP Syn Packet with options")
		if d.service != nil {
			// PreProcessServiceInterface
			if !d.service.PreProcessUDPAppPacket(p, conn.Context, conn) {
				p.Print(packet.PacketFailureService)
				return errors.New("pre service processing failed for UDP application packet")
			}
		}
		err = d.processApplicationUDPSynPacket(p, conn.Context, conn)

		if err != nil {
			return fmt.Errorf("Unable to send UDP Syn packet: %s", err)
		}

		if d.service != nil {
			// PostProcessServiceInterface
			if !d.service.PostProcessUDPAppPacket(p, nil, conn.Context, conn) {
				p.Print(packet.PacketFailureService)
				return errors.New("post service processing failed for application packet")
			}
		}
		zap.L().Debug("Varks: Sucessfully app udp syn is it?", zap.Error(err))

	case connection.UDPAckProcessed:
		// check for encryption and do the needful.
		if d.service != nil {
			// PostProcessServiceInterface
			if !d.service.PostProcessUDPAppPacket(p, nil, conn.Context, conn) {
				p.Print(packet.PacketFailureService)
				return errors.New("Encryption failed for application packet")
			}
		}
		// Send Packet on the wire.
		return conn.Writer.WriteSocket(p.Buffer)
	}
	// if not in the above two states, packets are queued.
	return nil
}

func (d *Datapath) appUDPRetrieveState(p *packet.Packet) (*connection.UDPConnection, error) {

	context, err := d.contextFromIP(true, p.SourceAddress.String(), p.Mark, p.SourcePort)
	if err != nil {
		return nil, errors.New("No context in app processing")
	}

	if conn, err := d.appOrigConnectionTracker.GetReset(p.L4FlowHash(), 0); err == nil {
		return conn.(*connection.UDPConnection), nil
	}
	return connection.NewUDPConnection(context, d.udpSocketWriter), nil
}

// processApplicationUDPSynPacket processes a single Syn Packet
func (d *Datapath) processApplicationUDPSynPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {

	// Create a token
	udpOptions := d.CreateUDPAuthMarker(packet.UDPSynMask)
	udpData, err := d.tokenAccessor.CreateSynPacketToken(context, &conn.Auth)

	if err != nil {
		return err
	}

	newPacket, err := d.clonePacket(udpPacket)
	if err != nil {
		return fmt.Errorf("Unable to clone packet: %s", err)
	}
	// Attach the UDP data and token
	newPacket.UDPTokenAttach(udpOptions, udpData)

	// send packet
	err = d.udpSocketWriter.WriteSocket(newPacket.Buffer)
	if err != nil {
		zap.L().Debug("Unable to send syn token on raw socket", zap.Error(err))
	}

	// Set the state indicating that we send out a Syn packet
	conn.SetState(connection.UDPSynSend)

	// Poplate the caches to track the connection
	hash := udpPacket.L4FlowHash()
	d.udpAppOrigConnectionTracker.AddOrUpdate(hash, conn)
	d.udpSourcePortConnectionCache.AddOrUpdate(newPacket.SourcePortHash(packet.PacketTypeApplication), conn)
	// Attach the tags to the packet and accept the packet

	zap.L().Debug("Varks: Application syn caches are being updated properly")
	return nil

}

func (d *Datapath) clonePacket(p *packet.Packet) (*packet.Packet, error) {

	// copy the ip and udp headers.

	newPacket := make([]byte, 28)
	zap.L().Debug("Clongin a new packet of length", zap.Reflect("length", len(p.Buffer)))
	p.FixupIPHdrOnDataModify(p.IPTotalLength, 28)
	_ = copy(newPacket, p.Buffer[:28])

	return packet.New(packet.PacketTypeApplication, newPacket, p.Mark)
}

// CreateUDPAuthMarker creates a UDP auth marker.
func (d *Datapath) CreateUDPAuthMarker(packetType uint8) []byte {
	// TODO Need a better marker. 20 byte marker.
	marker := make([]byte, 19)
	_ = copy(marker, []byte(UDPAuthMarker))
	fmt.Println("UDPAuth marker", marker)
	zap.L().Debug("Varks:  UDP Marker is: ", zap.Binary("marker", marker), zap.Reflect("length", len(marker)))
	marker = append(marker, byte(packetType))
	zap.L().Debug("Packet type is", zap.Reflect("packetType", byte(packetType)))
	zap.L().Debug("UDP marker with packet type is:", zap.Binary("marker", marker), zap.Reflect("length", len(marker)))

	return marker
}

// processApplicationSynAckPacket processes a UDP SynAck packet
func (d *Datapath) sendUDPSynAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {

	// check for service and configure encryption based on
	// policy that was resolved on network syn.
	if d.service != nil {
		// PreProcessServiceInterface
		if !d.service.PreProcessUDPAppPacket(udpPacket, context, conn) {
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

	udpPacket.CreateReverseFlowPacket()
	// Set the state for future reference
	conn.SetState(connection.UDPSynAckSent)

	// Attach the UDP data and token
	udpPacket.UDPTokenAttach(udpOptions, udpData)

	// send packet
	err = d.udpSocketWriter.WriteSocket(udpPacket.Buffer)
	if err != nil {
		zap.L().Debug("Unable to send synack token on raw socket", zap.Error(err))
	}

	// Setup ConnMark for encryption.
	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessUDPAppPacket(udpPacket, nil, context, conn) {
			udpPacket.Print(packet.PacketFailureService)
			return errors.New("post service processing failed for application packet")
		}
	}
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

	udpPacket.CreateReverseFlowPacket()

	// Attach the UDP data and token
	udpPacket.UDPTokenAttach(udpOptions, udpData)

	// send packet
	err = d.udpSocketWriter.WriteSocket(udpPacket.Buffer)
	if err != nil {
		zap.L().Debug("Unable to send ack token on raw socket", zap.Error(err))
	}

	conn.SetState(connection.UDPAckProcessed)

	// // Be optimistic and send Queued Packets
	// err = conn.TransmitQueuePackets()
	// if err != nil {
	// 	return fmt.Errorf("Unable to send queued packets: %s", err)
	// }

	if !conn.ServiceConnection {
		zap.L().Debug("Plumbing the conntrack (app) rule for flow", zap.String("flow", udpPacket.L4FlowHash()))

		if err = d.conntrackHdl.ConntrackTableUpdateMark(
			udpPacket.DestinationAddress.String(),
			udpPacket.SourceAddress.String(),
			udpPacket.IPProto,
			udpPacket.DestinationPort,
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

	// Be optimistic and Transmit Queued Packets
	for _, udpPacket := range conn.PacketQueue {
		// check for Encryption.
		if d.service != nil {
			// PostProcessServiceInterface
			if !d.service.PostProcessUDPAppPacket(udpPacket, nil, conn.Context, conn) {
				udpPacket.Print(packet.PacketFailureService)
				return errors.New("Encryption failed for queued application packet")
			}
		}

		err = conn.Writer.WriteSocket(udpPacket.Buffer)
		if err != nil {
			zap.L().Error("Unable to transmit Queued UDP packets", zap.Error(err))
		}
	}

	return err
}

// processNetworkUDPSynPacket processes a syn packet arriving from the network
func (d *Datapath) processNetworkUDPSynPacket(context *pucontext.PUContext, conn *connection.UDPConnection, udpPacket *packet.Packet) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	// what about external services ??????
	claims, err = d.tokenAccessor.ParsePacketToken(&conn.Auth, udpPacket.ReadUDPToken())
	if err != nil {
		//d.reportRejectedFlow(udpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidToken, nil, nil)
		return nil, nil, fmt.Errorf("UDP Syn packet dropped because of invalid token: %s", err)
	}

	// if there are no claims we must drop the connection and we drop the Syn
	// packet. The source will retry but we have no state to maintain here.
	if claims == nil {
		//	d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidToken, nil, nil)
		return nil, nil, errors.New("UDP Syn packet dropped because of no claims")
	}

	// txLabel, ok := claims.T.Get(enforcerconstants.TransmitterLabel)

	// Add the port as a label with an @ prefix. These labels are invalid otherwise
	// If all policies are restricted by port numbers this will allow port-specific policies
	claims.T.AppendKeyValue(enforcerconstants.PortNumberLabelString, strconv.Itoa(int(udpPacket.DestinationPort)))

	report, packet := context.SearchRcvRules(claims.T)
	if packet.Action.Rejected() {
		//d.reportRejectedFlow(tcpPacket, conn, txLabel, context.ManagementID(), context, collector.PolicyDrop, report, packet)
		return nil, nil, fmt.Errorf("connection rejected because of policy: %s", claims.T.String())
	}

	hash := udpPacket.L4FlowHash()
	// Update the connection state and store the Nonse send to us by the host.
	// We use the nonse in the subsequent packets to achieve randomization.
	conn.SetState(connection.UDPSynReceived)

	// conntrack
	d.udpNetOrigConnectionTracker.AddOrUpdate(hash, conn)
	d.udpAppReplyConnectionTracker.AddOrUpdate(udpPacket.L4ReverseFlowHash(), conn)

	// Record actions
	conn.ReportFlowPolicy = report
	conn.PacketFlowPolicy = packet

	return packet, claims, nil
}

func (d *Datapath) processNetworkUDPSynAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	// will come here only if a valid UDP token.

	// check for policy/report accordingly, for now return nil
	// Packets that have authorization information go through the auth path
	// Decode the JWT token using the context key
	claims, err = d.tokenAccessor.ParsePacketToken(&conn.Auth, udpPacket.ReadUDPToken())
	if err != nil {
		// d.reportRejectedFlow(tcpPacket, nil, collector.DefaultEndPoint, context.ManagementID(), context, collector.MissingToken, nil, nil)
		return nil, nil, fmt.Errorf("SynAck packet dropped because of bad claims: %s", err)
	}

	if claims == nil {
		// d.reportRejectedFlow(tcpPacket, nil, collector.DefaultEndPoint, context.ManagementID(), context, collector.MissingToken, nil, nil)
		return nil, nil, errors.New("SynAck packet dropped because of no claims")
	}

	_, packet := context.SearchTxtRules(claims.T, !d.mutualAuthorization)
	if packet.Action.Rejected() {
		// TODO: add report above
		// d.reportRejectedFlow(tcpPacket, conn, context.ManagementID(), conn.Auth.RemoteContextID, context, collector.PolicyDrop, report, packet)
		return nil, nil, fmt.Errorf("dropping because of reject rule on transmitter: %s", claims.T.String())
	}

	conn.SetState(connection.UDPSynAckReceived)
	// conntrack
	d.netReplyConnectionTracker.AddOrUpdate(udpPacket.L4FlowHash(), conn)

	return packet, claims, nil
}

func (d *Datapath) processNetworkUDPAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	claims, err = d.tokenAccessor.ParseAckToken(&conn.Auth, udpPacket.ReadUDPToken())
	if err != nil {
		// p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.InvalidFormat, nil, nil)
		return nil, nil, fmt.Errorf("ack packet dropped because signature validation failed: %s", err)
	}

	conn.SetState(connection.UDPAckProcessed)

	if !conn.ServiceConnection {
		zap.L().Debug("Plumb conntrack rule for flow:", zap.String("flow", udpPacket.L4FlowHash()))
		// Plumb connmark rule here.
		if err := d.conntrackHdl.ConntrackTableUpdateMark(
			udpPacket.SourceAddress.String(),
			udpPacket.DestinationAddress.String(),
			udpPacket.IPProto,
			udpPacket.SourcePort,
			udpPacket.DestinationPort,
			constants.DefaultConnMark,
		); err != nil {
			zap.L().Error("Failed to update conntrack table after ack packet")
		}
	}
	// p.reportAcceptedFlow(flowProperties, conn, conn.Auth.RemoteContextID, puContext.ManagementID(), puContext, conn.ReportFlowPolicy, conn.PacketFlowPolicy)

	return nil, nil, nil
}
