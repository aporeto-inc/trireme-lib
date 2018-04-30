package nfqdatapath

// Go libraries
import (
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/controller/pkg/connection"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/packet"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/pucontext"
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

	// Idealy all packets from network should only be auth packets.
	var conn *connection.UDPConnection
	udpPacketType := p.GetUDPType()

	switch udpPacketType & packet.TCPSynAckMask {
	case packet.TCPSynMask:
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

	case packet.TCPSynAckMask:
		conn, err = d.netSynAckUDPRetrieveState(p)
		if err != nil {
			if d.packetLogs {
				zap.L().Debug("Packet Rejected",
					zap.String("flow", p.L4FlowHash()),
				)
			}
			// flush the packetQueue on errors.
			if conn != nil {
				conn.DropPackets()
			}
			return err
		}

	case packet.TCPAckMask:
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
		// what to do here?: on server side maintain a queue, No.
		return fmt.Errorf("Dropping packet, since Auth in progress")

	}

	err = d.processNetUDPPacket(p, conn.Context, conn)

	// check for encryption and do it later on..

	return err
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

	conn, err := d.sourcePortConnectionCache.GetReset(p.SourcePortHash(packet.PacketTypeNetwork), 0)
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

// processNetUDPPacket processes a network TCP packet and dispatches it to different methods based on the flags
func (d *Datapath) processNetUDPPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {

	if conn == nil {
		return nil
	}

	udpPacketType := udpPacket.GetUDPType()
	// Update connection state in the internal state machine tracker
	switch udpPacketType & packet.TCPSynAckMask {

	case packet.TCPSynMask:
		err = d.processNetworkUDPSynPacket(context, conn, udpPacket)
		if err != nil {
			return err
		}
		err = d.sendUDPSynAckPacket(udpPacket, context, conn)
		if err != nil {
			return err
		}

	case packet.TCPAckMask:
		err = d.processNetworkUDPAckPacket(udpPacket, context, conn)
		if err != nil {
			zap.L().Error("Error during authorization", zap.Error(err))
			return nil
		}
		// ack is processed, mark connmark rule and let other packets go through.
		return nil

	case packet.TCPSynAckMask:
		err = d.processNetworkUDPSynAckPacket(udpPacket, context, conn)
		if err != nil {
			zap.L().Error("UDP Syn ack failed with", zap.Error(err))
			return nil
		}
		err = d.sendUDPAckPacket(udpPacket, context, conn)
		if err != nil {
			zap.L().Error("Unable to send udp Syn ack failed", zap.Error(err))
			return nil
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

	var conn *connection.UDPConnection
	conn, err = d.appUDPRetrieveState(p)
	if err != nil {
		return fmt.Errorf("Recieved packet from unenforced process: %s", err)
	}

	switch conn.GetState() {

	case connection.UDPSynSend:
		// connection not authorized yet. queue the packets and start handshake.

		err = d.processApplicationUDPSynPacket(p, conn.Context, conn)

	case connection.UDPAckProcessed:
		// send the packet on the wire.
		err = conn.Writer.WriteSocket(p.Buffer)
		return err
	}

	// Accept the packet
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
	udpOptions := d.CreateUDPAuthMarker(packet.TCPSynMask)
	udpData, err := d.tokenAccessor.CreateSynPacketToken(context, &conn.Auth)

	if err != nil {
		return err
	}

	newPacket, err := d.clonePacket(udpPacket)
	if err != nil {
		return fmt.Errorf("Unable to clone packet: %s", err)
	}
	// Queue the old packets.
	conn.QueuePackets(udpPacket)

	// Attach the UDP data and token
	newPacket.UDPDataAttach(udpOptions, udpData)

	// send packet
	err = d.udpSocketWriter.WriteSocket(newPacket.Buffer)
	if err != nil {
		zap.L().Debug("Unable to send synack token on raw socket", zap.Error(err))
	}

	// Set the state indicating that we send out a Syn packet
	conn.SetState(connection.UDPSynSend)

	// Poplate the caches to track the connection
	hash := udpPacket.L4FlowHash()
	d.udpAppOrigConnectionTracker.AddOrUpdate(hash, conn)
	d.udpSourcePortConnectionCache.AddOrUpdate(udpPacket.SourcePortHash(packet.PacketTypeApplication), conn)
	// Attach the tags to the packet and accept the packet

	return nil

}

func (d *Datapath) clonePacket(p *packet.Packet) (*packet.Packet, error) {

	newPacket := make([]byte, len(p.Buffer))
	_ = copy(newPacket, p.Buffer)
	return packet.New(packet.PacketTypeApplication, newPacket, p.Mark)
}

// CreateUDPAuthMarker creates a UDP auth marker.
func (d *Datapath) CreateUDPAuthMarker(packetType uint8) []byte {
	// TODO Need a better marker. 20 byte marker.
	marker := make([]byte, 20)
	_ = copy(marker, []byte(UDPAuthMarker))
	marker = append(marker, byte(packetType))

	return marker
}

// processApplicationSynAckPacket processes an application SynAck packet
func (d *Datapath) sendUDPSynAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {

	// Create UDP Option
	udpOptions := d.CreateUDPAuthMarker(packet.TCPSynAckMask)

	udpData, err := d.tokenAccessor.CreateSynAckPacketToken(context, &conn.Auth)

	if err != nil {
		return err
	}

	udpPacket.CreateReverseFlowPacket()
	// Set the state for future reference
	conn.SetState(connection.UDPSynAckSent)

	// Attach the UDP data and token
	udpPacket.UDPDataAttach(udpOptions, udpData)

	// send packet
	err = d.udpSocketWriter.WriteSocket(udpPacket.Buffer)
	if err != nil {
		zap.L().Debug("Unable to send synack token on raw socket", zap.Error(err))
	}
	return nil

}

func (d *Datapath) sendUDPAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {

	// Create UDP Option
	udpOptions := d.CreateUDPAuthMarker(packet.TCPAckMask)

	udpData, err := d.tokenAccessor.CreateAckPacketToken(context, &conn.Auth)

	if err != nil {
		return err
	}

	udpPacket.CreateReverseFlowPacket()

	// Attach the UDP data and token
	udpPacket.UDPDataAttach(udpOptions, udpData)

	// send packet
	err = d.udpSocketWriter.WriteSocket(udpPacket.Buffer)
	if err != nil {
		zap.L().Debug("Unable to send synack token on raw socket", zap.Error(err))
	}

	conn.SetState(connection.UDPAckProcessed)

	// Be optimistic and send Queued Packets
	err = conn.TransmitQueuePackets()

	// Plumb connmark rule.

	return err
}

// processNetworkUDPSynPacket processes a syn packet arriving from the network
func (d *Datapath) processNetworkUDPSynPacket(context *pucontext.PUContext, conn *connection.UDPConnection, udpPacket *packet.Packet) (err error) {

	// what about external services ??????
	_, err = d.tokenAccessor.ParsePacketToken(&conn.Auth, udpPacket.ReadUDPToken())

	// use claims.
	// If the token signature is not valid,
	// we must drop the connection and we drop the Syn packet. The source will
	// retry but we have no state to maintain here.
	// if err != nil {
	// 	d.reportRejectedFlow(udpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidToken, nil, nil)
	// 	return nil, nil, fmt.Errorf("Syn packet dropped because of invalid token: %s", err)
	// }

	// if there are no claims we must drop the connection and we drop the Syn
	// packet. The source will retry but we have no state to maintain here.
	// if claims == nil {
	// 	d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidToken, nil, nil)
	// 	return nil, nil, errors.New("Syn packet dropped because of no claims")
	// }

	hash := udpPacket.L4FlowHash()
	// Update the connection state and store the Nonse send to us by the host.
	// We use the nonse in the subsequent packets to achieve randomization.
	conn.SetState(connection.UDPSynReceived)

	// conntrack
	d.udpNetOrigConnectionTracker.AddOrUpdate(hash, conn)
	d.udpAppReplyConnectionTracker.AddOrUpdate(udpPacket.L4ReverseFlowHash(), conn)

	// Accept the connection

	// prior to this check for policy/encryption etc
	return nil
}

func (d *Datapath) processNetworkUDPSynAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {

	// will come here only if a valid UDP token.

	// check for policy/report accordingly, for now return nil
	// Packets that have authorization information go through the auth path
	// Decode the JWT token using the context key
	_, err = d.tokenAccessor.ParsePacketToken(&conn.Auth, udpPacket.ReadUDPToken())

	// check polices and claims

	conn.SetState(connection.UDPSynAckReceived)
	// conntrack
	d.netReplyConnectionTracker.AddOrUpdate(udpPacket.L4FlowHash(), conn)

	return nil
}

func (d *Datapath) processNetworkUDPAckPacket(udppacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {

	_, err = d.tokenAccessor.ParseAckToken(&conn.Auth, udppacket.ReadUDPToken())
	if err != nil {
		// report rejected flow.
		return err
	}
	conn.SetState(connection.UDPAckProcessed)

	// Plumb connmark rule here.

	return nil
}
