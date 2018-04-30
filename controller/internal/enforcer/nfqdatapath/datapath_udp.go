package nfqdatapath

// Go libraries
import (
	"encoding/binary"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/connection"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/packet"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/pucontext"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/tokens"
)

const (
	UDPAuthMarker    = "n30njxq7bmiwr6dtxqq"
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
			zap.String("Flags", packet.TCPFlagsToStr(p.TCPFlags)),
			zap.Error(err),
		)
	}

	var conn *connection.UDPConnection
	udpPacketType := p.GetUDPType()
	switch udpPacketType & packet.TCPSynAckMask  {
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
        conn.SetState(connection.UDPSynRecieved)

	case packet.TCPSynAckMask:
		conn, err = d.netSynAckUDPRetrieveState(p)
		if err != nil {
			if d.packetLogs {
				zap.L().Debug("Packet Rejected",
					zap.String("flow", p.L4FlowHash()),
				)
            }
            // flush the packetQueue on errors.
            if (conn != nil)
                conn.DropPackets()
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
     case default:
        // what to do here?: on server side maintain a queue, No.
        return fmt.Errorf("Dropping packet, since Auth in progress")

	}

    _, _, err := d.processNetUDPPacket(packet, context, connection)

    // check for encryption and do it later on..

    return err
}


func (d *DataPath) netSynUDPRetrieveState(p *packet.Packet) (*connection.UDPConnection, error) {

	context, err := d.contextFromIP(false, p.DestinationAddress.String(), p.Mark, p.DestinationPort)
	if err != nil {
		zap.L().Debug("Recieved Packets from unenforcerd process")
        return err
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
    var err error
    udpPacketType := p.GetUDPType()
	// Update connection state in the internal state machine tracker
	switch udpPacketType & packet.TCPSynAckMask {

	case packet.TCPSynMask:
		err = d.processNetworkUDPSynPacket(context, conn, udpPacket)
        if err != nil {
            return err
        }
        err = d.SendUDPSynAckPacket(p, conn, context)
        if (err != nil) {
            return err
        }


	case packet.TCPAckMask:
		err = d.processNetworkUDPAckPacket(context, conn, udpPacket)
        if (err != nil) {
            zap.L().Error("Error during authorization", zap.Error(err))
            return nil
        }
        // ack is processed, mark connmark rule and let other packets go through.
        return nil

	case packet.TCPSynAckMask:
		err =  d.processNetworkUDPSynAckPacket(context, conn, udpPacket)
        if err != nil {
            zap.L().Error("UDP Syn ack failed with", zap.Error(err))
            return nil
        }
        err = d.SendUDPAckPacket(p, conn, context)
        if (err != nil) {
            zap.L().Error("Unable to send udp Syn ack failed", zap.Error(err))
            return nil
        }
	default: // Ignore any other packet
        // shouldnt come here
        return nil
	}
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
    conn, err := d.appUDPRetrieveState(p)
    if err != nil {
        return err
    }

    switch conn.GetState() {

    case connection.UDPSynSend:
        _, err = d.processApplicationTCPPacket(p, conn.Context, conn)

    case connection.UDPAckProcessed:
        // send the packet on the wire.
        err = conn.WriteSocket(p.Buffer)
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
		return conn.(*connection.TCPConnection), nil
	}
	return connection.NewUDPConnection(context), nil
}




// processApplicationUDPSynPacket processes a single Syn Packet
func (d *Datapath) processApplicationUDPSynPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (interface{}, error) {

    // Create a token
    udpOptions := d.CreateUDPAuthMarker(packet.TCPSynMask)
	udpData, err := d.tokenAccessor.CreateSynPacketToken(context, &conn.Auth)

	if err != nil {
		return nil, err
	}

    newPacket := d.clonePacket(udpPacket)
	// Set the state for future reference

	// Attach the UDP data and token
	err = newPacket.UDPDataAttach(udpOptions, udpData)
	if err != nil {
		return fmt.Errorf("Unable to attach udp data %s", err)
	}

	// send packet
	err = d.udpSocketWriter.WriteSocket(newPacket.Buffer)
	if err != nil {
		zap.L().Debug("Unable to send synack token on raw socket", zap.Error(err))
	}
	return nil

	// Set the state indicating that we send out a Syn packet
	conn.SetState(connection.UDPSynSend)

	// Poplate the caches to track the connection
	hash := tcpPacket.L4FlowHash()
	d.udpAppOrigConnectionTracker.AddOrUpdate(hash, conn)
	d.udpSourcePortConnectionCache.AddOrUpdate(udpPacket.SourcePortHash(packet.PacketTypeApplication), conn)
    // Attach the tags to the packet and accept the packet

	return nil

}

func (d *Datapath) createReverseFlowPacket(p *packet.Packet) error {

	srcAddr := make([]byte, len(p.SourceAddress))
	destAddr := make([]byte, len(p.DestinationAddress))
	srcPort := make([]byte, len(p.SourcePort))
	dstPort := make([]byte, len(p.DestinationPort))

	// copy the fields
	binary.BigEndian.PutUint32(p.Buffer[packet.ipSourceAddrPos:packet.ipSourceAddrPos+4], destAddr)
	binary.BigEndian.PutUint32(p.Buffer[packet.ipDestAddrPos:packet.ipDestAddrPos+4], srcAddr)
	binary.BigEndian.PutUint16(p.Buffer[packet.tcpSourcePortPos:packet.tcpSourcePortPos+2], destPort)
	binary.BigEndian.PutUint16(p.Buffer[packet.tcpDestPortPos:packet.tcpDestPortPos+2], srcPort)

	p.UpdateIPChecksum()

	p.UpdateUDPChecksum()
}

func (d *Datapath) clonePacket(p *packet.Packet) (*packet.Packet) {

    newPacket := make([]byte, len(p.Buffer))
    _ := copy(newPacket, p.Buffer)
    return newPacket
}


// CreateUDPAuthMarker creates a UDP auth marker.
func (d *Datapath) CreateUDPAuthMarker(packetType uint8) []byte {
	// TODO Need a better marker. 20 byte marker.
    marker := make([]byte, 20);
    _ := copy(udpAuthMarker, []byte(UDPAuthMarker))
    marker = append(marker, byte(packetType))

    return marker
}

// processApplicationSynAckPacket processes an application SynAck packet
func (d *Datapath) sendUDPSynAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) (interface{}, error) {

	// Create UDP Option
	udpOption := d.CreateUDPAuthMarker(packet.TCPSynAckMask)

	udpData, err := d.tokenAccessor.CreateSynAckPacketToken(context, &conn.Auth)

	if err != nil {
		return nil, err
	}

	newPacket := d.createReverseFlowPacket(udpPacket)
	// Set the state for future reference
	conn.SetState(connection.TCPSynAckSend)

	// Attach the UDP data and token
	err = newPacket.UDPDataAttach(udpOptions, udpData)
	if err != nil {
		return fmt.Errorf("Unable to attach udp data %s", err)
	}

	// send packet
	err = d.udpSocketWriter.WriteSocket(newPacket.Buffer)
	if err != nil {
		zap.L().Debug("Unable to send synack token on raw socket", zap.Error(err))
	}
	return nil

}

func (d *Datapath) sendUDPAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) (interface{}, error) {

	// Create UDP Option
	udpOption := d.CreateUDPAuthMarker(packet.TCPAckMask)

	udpData, err := d.tokenAccessor.CreateAckPacketToken(context, &conn.Auth)

	if err != nil {
		return nil, err
	}

	newPacket := d.createReverseFlowPacket(udpPacket)

	// Attach the UDP data and token
	err = newPacket.UDPDataAttach(udpOptions, udpData)
	if err != nil {
		return fmt.Errorf("Unable to attach udp data %s", err)
	}

	// send packet
	err = d.udpSocketWriter.WriteSocket(newPacket.Buffer)
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
func (d *Datapath) processNetworkUDPSynPacket(context *pucontext.PUContext, conn *connection.TCPConnection, udpPacket *packet.Packet) (err error) {

    // what about external services ??????
	claims, err = d.tokenAccessor.ParsePacketToken(&conn.Auth, udpPacket.ReadUDPToken())

	// If the token signature is not valid,
	// we must drop the connection and we drop the Syn packet. The source will
	// retry but we have no state to maintain here.
	if err != nil {
		d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidToken, nil, nil)
		return nil, nil, fmt.Errorf("Syn packet dropped because of invalid token: %s", err)
	}

	// if there are no claims we must drop the connection and we drop the Syn
	// packet. The source will retry but we have no state to maintain here.
	// if claims == nil {
	// 	d.reportRejectedFlow(tcpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidToken, nil, nil)
	// 	return nil, nil, errors.New("Syn packet dropped because of no claims")
	// }

	hash := tcpPacket.L4FlowHash()
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

func (d *Datapath) processNetworkUDPSynAckPacket(udppacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {

        // will come here only if a valid UDP token.

        // check for policy/report accordingly, for now return nil
	// Packets that have authorization information go through the auth path
	// Decode the JWT token using the context key
	claims, err = d.tokenAccessor.ParsePacketToken(&conn.Auth, udppacket.ReadUDPToken())

	hash := tcpPacket.L4FlowHash()

    // check polices and claims

    conn.SetState(connection.UDPSynAckReceived)
	// conntrack
	d.netReplyConnectionTracker.AddOrUpdate(tcpPacket.L4FlowHash(), conn)

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

// contextFromIP returns the PU context from the default IP if remote. Otherwise
// it returns the context from the port or mark values of the packet. Synack
// packets are again special and the flow is reversed. If a container doesn't supply
// its IP information, we use the default IP. This will only work with remotes
// and Linux processes.
func (d *Datapath) contextFromIP(app bool, packetIP string, mark string, port uint16) (*pucontext.PUContext, error) {

	if d.puFromIP != nil {
		return d.puFromIP, nil
	}

	if app {
		pu, err := d.puFromMark.Get(mark)
		if err != nil {
			return nil, fmt.Errorf("pu context cannot be found using mark %s: %s", mark, err)
		}
		return pu.(*pucontext.PUContext), nil
	}

	contextID, err := d.contextIDFromPort.GetSpecValueFromPort(port)
	if err != nil {
		return nil, fmt.Errorf("pu contextID cannot be found using port %d: %s", port, err)
	}

	pu, err := d.puFromContextID.Get(contextID)
	if err != nil {
		return nil, fmt.Errorf("unable to find contextID: %s", contextID)
	}

	return pu.(*pucontext.PUContext), nil
}

// ProcessNetworkPacket is a dummy function
func (d *Datapath) ProcessNetworkPacket(p *packet.Packet) error {
	return nil

}

// ProcessApplicationPacket is a dummy function
func (d *Datapath) ProcessApplicationPacket(p *packet.Packet) error {
	return nil
}
