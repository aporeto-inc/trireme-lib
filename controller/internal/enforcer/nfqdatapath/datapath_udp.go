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
	UDPAuthMarker    = "n30njxq7bmiwr6dtxqqr"
	UDPAuthMarkerLen = 20
)

// ProcessNetworkUDPPacket processes packets arriving from network and are destined to the application
func (d *Datapath) ProcessNetworkUDPPacket(p *packet.Packet) (err error) {

	if d.packetLogs {
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

	var conn *connection.UDPConnection

	// find the flow--- look in the cache and process the connection state
	conn, err := d.netUDPRetrieveState(p)
	if err != nil {
		return fmt.Errorf("Something is wrong -- log")
	}

	if conn == nil {
		// queue packet and perform aporeto handshake.
		conn, err = d.netUDPRetrieveConn(p)
		conn.SetState(connection.UDPSynRecieved)
		conn.queuePackets(p)

	} else {
		switch conn.GetState() {
		case connection.UDPSynRecieved:
			// add udp data (aporeto ID, token)
			// update the connection cache and change the state.
			err := d.processNetworkUDPSynPacket(p, context, conn)
			if err != nil {
				zap.L().Error("Dropping packet since no option found", zap.Error(err))
				return err
			}
			// send syn ack auth   add retrasmits later on.
			err := d.SendUDPSynAck(p, context, conn)
			if err != nil {
				zap.L().Error("Unable to send udp syn ack token", zap.Error(err))
				return fmt.Errorf("Unable to send UDP syn ack token", zap.Error(err))
			}
			conn.SetState(connection.UDPSynAckSent)

		case connection.UDPSynAckRecieved:
			err := d.processNetworkUDPSynAckPacket(p, context, conn)
			if err != nil {

			}
			//
		case connection.UDPAckProcessed:
			err := d.processNetworkUDPAckPacket(p, context, conn)
			if err != nil {

			}
		default:
			fmt.Println("Recieved packet in state ???", conn.GetState())
		}

	}

	p.Print(packet.PacketStageIncoming)

	// Accept the packet
	p.UpdateUDPChecksum()

	p.Print(packet.PacketStageOutgoing)

	return nil
}

func (d *DataPath) netUDPRetrieveConn(p *packet.Packet) (*connection.UDPConnection, error) {

	context, err := d.contextFromIP(false, p.DestinationAddress.String(), p.Mark, p.DestinationPort)
	if err != nil {
		zap.L().Debug("Recieved Packets from unenforcerd process")
	}
	if conn, err := d.netOrigConnectionTracker.GetReset(p.L4FlowHash(), 0); err == nil {
		return conn.(*connection.UDPConnection), nil
	}
	return connection.NewUDPConnection(context, d.udpSocketWriter), nil
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

	conn.Lock()
	defer conn.Unlock()

	p.Print(packet.PacketStageIncoming)

	// if d.service != nil {
	// 	// PreProcessServiceInterface
	// 	if !d.service.PreProcessTCPAppPacket(p, conn.Context, conn) {
	// 		p.Print(packet.PacketFailureService)
	// 		return errors.New("pre service processing failed for application packet")
	// 	}
	// }

	p.Print(packet.PacketStageAuth)

	// Match the tags of the packet against the policy rules - drop if the lookup fails
	action, err := d.processApplicationTCPPacket(p, conn.Context, conn)
	if err != nil {
		if d.packetLogs {
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
		if !d.service.PostProcessTCPAppPacket(p, action, conn.Context, conn) {
			p.Print(packet.PacketFailureService)
			return errors.New("post service processing failed for application packet")
		}
	}

	// Accept the packet
	p.UpdateTCPChecksum()
	p.Print(packet.PacketStageOutgoing)
	return nil
}

// processApplicationSynPacket processes a single Syn Packet
func (d *Datapath) processApplicationUDPSynPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (interface{}, error) {

	// Create a token
	udpData, err := d.tokenAccessor.CreateSynPacketToken(context, &conn.Auth)

	if err != nil {
		return nil, err
	}

	// Set the state indicating that we send out a Syn packet
	conn.SetState(connection.TCPSynSend)

	// Poplate the caches to track the connection
	hash := tcpPacket.L4FlowHash()
	d.appOrigConnectionTracker.AddOrUpdate(hash, conn)
	d.sourcePortConnectionCache.AddOrUpdate(udpPacket.SourcePortHash(packet.PacketTypeApplication), conn)
	// Attach the tags to the packet and accept the packet
	return nil, tcpPacket.TCPDataAttach(tcpOptions, tcpData)

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

func (d *Datapath) CreateUDPAuthMarker() []byte {

	return UDPAuthMarker
}

// processApplicationSynAckPacket processes an application SynAck packet
func (d *Datapath) processApplicationSynAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) (interface{}, error) {

	// Create UDP Option
	udpOption := d.CreateUDPAuthMarker()

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

// processNetworkUDPSynPacket processes a syn packet arriving from the network
func (d *Datapath) processNetworkUDPSynPacket(context *pucontext.PUContext, conn *connection.TCPConnection, udpPacket *packet.Packet) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	// check for UDP Aporeto marker.
	// Incoming packets that don't have our options are candidates to be processed
	// as external services.
	if err = udpPacket.CheckUDPAuthenticationMarker(); err != nil {
		return fmt.Errorf("No UDP Auth marker found: %s", err)
	}

	// Packets that have authorization information go through the auth path
	// Decode the JWT token using the context key
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
	conn.SetState(connection.TCPSynReceived)

	// conntrack
	d.netOrigConnectionTracker.AddOrUpdate(hash, conn)
	d.appReplyConnectionTracker.AddOrUpdate(udpPacket.L4ReverseFlowHash(), conn)

	// Accept the connection
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
