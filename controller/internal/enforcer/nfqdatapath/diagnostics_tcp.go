package nfqdatapath

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/aporeto-inc/gopkt/packet/raw"
	"github.com/aporeto-inc/gopkt/packet/tcp"
	"github.com/aporeto-inc/gopkt/routing"
	"github.com/phayes/freeport"
	"github.com/vmihailenco/msgpack"
	"go.aporeto.io/trireme-lib/collector"
	enforcerconstants "go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	tpacket "go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/crypto"
	"go.uber.org/zap"
)

func (d *Datapath) initiateDiagnostics(_ context.Context, contextID string, pingConfig *policy.PingConfig) error {

	if pingConfig == nil {
		return nil
	}

	zap.L().Debug("Initiating diagnostics (syn)")

	srcIP, err := getSrcIP(pingConfig.IP)
	if err != nil {
		return fmt.Errorf("unable to get source ip: %v", err)
	}

	conn, err := createConnection(srcIP, pingConfig.IP)
	if err != nil {
		return fmt.Errorf("unable to dial on app syn: %v", err)
	}
	defer conn.Close() // nolint:errcheck

	item, err := d.puFromContextID.Get(contextID)
	if err != nil {
		return fmt.Errorf("unable to find context with ID %s in cache: %v", contextID, err)
	}

	context, ok := item.(*pucontext.PUContext)
	if !ok {
		return fmt.Errorf("invalid pu context: %v", contextID)
	}

	for i := 1; i <= pingConfig.Requests; i++ {
		for _, ports := range pingConfig.Ports {
			for dstPort := ports.Min; dstPort <= ports.Max; dstPort++ {
				if err := d.sendSynPacket(context, pingConfig, conn, srcIP, dstPort, i); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// sendSynPacket sends tcp syn packet to the socket. It also dispatches a report.
func (d *Datapath) sendSynPacket(context *pucontext.PUContext, pingConfig *policy.PingConfig, conn *diagnosticsConnection, srcIP net.IP, dstPort uint16, request int) error {

	tcpConn := connection.NewTCPConnection(context, nil)
	tcpConn.Secrets = d.secrets()

	claimsHeader := claimsheader.NewClaimsHeader(
		claimsheader.OptionPingType(pingConfig.Type),
	)

	tcpData, err := d.tokenAccessor.CreateSynPacketToken(context, &tcpConn.Auth, claimsHeader, d.secrets())
	if err != nil {
		return fmt.Errorf("unable to create syn token: %v", err)
	}

	srcPort, err := freeport.GetFreePort()
	if err != nil {
		return fmt.Errorf("unable to get free source port: %v", err)
	}

	p, err := constructPacket(conn, srcIP, pingConfig.IP, uint16(srcPort), dstPort, tcp.Syn, tcpData)
	if err != nil {
		return fmt.Errorf("unable to construct syn packet: %v", err)
	}

	sessionID, err := crypto.GenerateRandomString(20)
	if err != nil {
		return err
	}

	if err := conn.Write(p); err != nil {
		return fmt.Errorf("unable to send syn packet: %v", err)
	}

	tcpConn.PingConfig = &connection.PingConfig{
		StartTime: time.Now(),
		Type:      pingConfig.Type,
		SessionID: sessionID,
		Request:   request,
	}

	d.sendOriginPingReport(
		sessionID,
		d.agentVersion.String(),
		flowTuple(
			tpacket.PacketTypeApplication,
			srcIP.String(),
			pingConfig.IP.String(),
			uint16(srcPort),
			dstPort,
		),
		context,
		pingConfig.Type,
		len(tcpData),
		request,
	)

	tcpConn.SetState(connection.TCPSynSend)
	d.sourcePortConnectionCache.AddOrUpdate(
		packetTuple(tpacket.PacketTypeApplication, srcIP.String(), pingConfig.IP.String(), uint16(srcPort), dstPort),
		tcpConn,
	)

	return nil
}

// processDiagnosticNetSynPacket should only be called when the packet is recognized as a diagnostic syn packet.
func (d *Datapath) processDiagnosticNetSynPacket(
	context *pucontext.PUContext,
	tcpConn *connection.TCPConnection,
	tcpPacket *tpacket.Packet,
	claims *tokens.ConnectionClaims,
) error {

	ch := claims.H.ToClaimsHeader()
	tcpConn.PingConfig.Type = ch.PingType()
	tcpConn.SetState(connection.TCPSynReceived)

	zap.L().Debug("Processing diagnostic network syn packet",
		zap.String("pingType", ch.PingType().String()),
	)

	if ch.PingType() == claimsheader.PingTypeDefaultIdentityPassthrough {
		zap.L().Debug("Processing diagnostic network syn packet: defaultpassthrough")

		tcpConn.PingConfig.Passthrough = true
		d.appReplyConnectionTracker.AddOrUpdate(tcpPacket.L4ReverseFlowHash(), tcpConn)
		return nil
	}

	conn, err := createConnection(tcpPacket.DestinationAddress(), tcpPacket.SourceAddress())
	if err != nil {
		return fmt.Errorf("unable to dial on net syn: %v", err)
	}
	defer conn.Close() // nolint:errcheck

	var tcpData []byte
	// If diagnostic type is custom, we add custom payload.
	// Else, we add default payload.
	if ch.PingType() == claimsheader.PingTypeCustomIdentity {
		ci := &customIdentity{
			AgentVersion:         d.agentVersion.String(),
			TransmitterID:        context.ManagementID(),
			TransmitterNamespace: context.ManagementNamespace(),
			FlowTuple: flowTuple(
				tpacket.PacketTypeApplication,
				tcpPacket.SourceAddress().String(),
				tcpPacket.DestinationAddress().String(),
				tcpPacket.SourcePort(),
				tcpPacket.DestPort(),
			),
		}
		tcpData, err = ci.encode()
		if err != nil {
			return err
		}
	} else {
		tcpData, err = d.tokenAccessor.CreateSynAckPacketToken(context, &tcpConn.Auth, ch, d.secrets())
		if err != nil {
			return fmt.Errorf("unable to create default synack token: %v", err)
		}
	}

	p, err := constructPacket(
		conn,
		tcpPacket.DestinationAddress(),
		tcpPacket.SourceAddress(),
		tcpPacket.DestPort(),
		tcpPacket.SourcePort(),
		tcp.Syn|tcp.Ack,
		tcpData,
	)
	if err != nil {
		return fmt.Errorf("unable to construct synack packet: %v", err)
	}

	if err := conn.Write(p); err != nil {
		return fmt.Errorf("unable to send synack packet: %v", err)
	}

	tcpConn.SetState(connection.TCPSynAckSend)
	return nil
}

// constructPacket constructs a valid packet that can be sent on wire.
func constructPacket(conn *diagnosticsConnection, srcIP, dstIP net.IP, srcPort, dstPort uint16, flag tcp.Flags, tcpData []byte) ([]byte, error) {

	// tcp.
	tcpPacket := tcp.Make()
	tcpPacket.SrcPort = srcPort
	tcpPacket.DstPort = dstPort
	tcpPacket.Flags = flag
	tcpPacket.Seq = rand.Uint32()
	tcpPacket.WindowSize = 0xAAAA
	tcpPacket.Options = []tcp.Option{
		{
			Type: tcp.MSS,
			Len:  4,
			Data: []byte{0x05, 0x8C},
		}, {
			Type: 34, // tfo
			Len:  enforcerconstants.TCPAuthenticationOptionBaseLen,
			Data: make([]byte, 2),
		},
	}
	tcpPacket.DataOff = uint8(7) // 5 (header size) + 2 * (4 byte options)

	// payload.
	payload := raw.Make()
	payload.Data = tcpData

	tcpPacket.SetPayload(payload) // nolint:errcheck

	// construct the wire packet
	buf, err := conn.constructWirePacket(srcIP, dstIP, tcpPacket, payload)
	if err != nil {
		return nil, fmt.Errorf("unable to encode packet to wire format: %v", err)
	}

	return buf, nil
}

// processDiagnosticNetSynAckPacket should only be called when the packet is recognized as a diagnostic synack packet.
func (d *Datapath) processDiagnosticNetSynAckPacket(
	context *pucontext.PUContext,
	tcpConn *connection.TCPConnection,
	tcpPacket *tpacket.Packet,
	claims *tokens.ConnectionClaims,
	ext bool,
	custom bool,
) error {
	zap.L().Debug("Processing diagnostic network synack packet",
		zap.Bool("externalNetwork", ext),
		zap.Bool("customPayload", custom),
		zap.String("pingType", tcpConn.PingConfig.Type.String()),
	)

	if tcpConn.GetState() == connection.TCPSynAckReceived {
		zap.L().Debug("Ignoring duplicate synack packets")
		return nil
	}

	receiveTime := time.Since(tcpConn.PingConfig.StartTime)
	tcpConn.SetState(connection.TCPSynAckReceived)

	// Synack from externalnetwork.
	if ext {
		tcpConn.PingConfig.Passthrough = true
		d.sendReplyPingReport(&customIdentity{}, tcpConn, context, receiveTime.String(), len(tcpPacket.ReadTCPData()))
		return nil
	}

	// Synack from an endpoint with custom identity enabled.
	if custom {
		ci := &customIdentity{}
		if err := ci.decode(tcpPacket.ReadTCPData()); err != nil {
			return err
		}

		d.sendReplyPingReport(ci, tcpConn, context, receiveTime.String(), len(tcpPacket.ReadTCPData()))
		return nil
	}

	txtID, ok := claims.T.Get(enforcerconstants.TransmitterLabel)
	if !ok {
		return fmt.Errorf("missing transmitter label")
	}

	ci := &customIdentity{
		TransmitterID: txtID,
	}

	d.sendReplyPingReport(ci, tcpConn, context, receiveTime.String(), len(tcpPacket.ReadTCPData()))

	if tcpConn.PingConfig.Type == claimsheader.PingTypeDefaultIdentityPassthrough {
		zap.L().Debug("Processing diagnostic network synack packet: defaultpassthrough")
		tcpConn.PingConfig.Passthrough = true
		return nil
	}

	return nil
}

// getSrcIP returns the interface ip that can reach the destination.
func getSrcIP(dstIP net.IP) (net.IP, error) {

	route, err := routing.RouteTo(dstIP)
	if err != nil || route == nil {
		return nil, fmt.Errorf("no route found for destination %s: %v", dstIP.String(), err)
	}

	ip, err := route.GetIfaceIPv4Addr()
	if err != nil {
		return nil, fmt.Errorf("unable to get interface ip address: %v", err)
	}

	return ip, nil
}

// flowTuple returns the tuple based on the stage in format <sip:dip:spt:dpt> or <dip:sip:dpt:spt>
func flowTuple(stage uint64, srcIP, dstIP string, srcPort, dstPort uint16) string {

	if stage == tpacket.PacketTypeNetwork {
		return fmt.Sprintf("%s:%s:%s:%s", dstIP, srcIP, strconv.Itoa(int(dstPort)), strconv.Itoa(int(srcPort)))
	}

	return fmt.Sprintf("%s:%s:%s:%s", srcIP, dstIP, strconv.Itoa(int(srcPort)), strconv.Itoa(int(dstPort)))
}

// packetTuple returns the tuple based on the stage in format <sip:spt> or <dip:dpt>
func packetTuple(stage uint64, srcIP, dstIP string, srcPort, dstPort uint16) string {

	if stage == tpacket.PacketTypeNetwork {
		return dstIP + ":" + strconv.Itoa(int(dstPort))
	}

	return srcIP + ":" + strconv.Itoa(int(srcPort))
}

// sendOriginPingReport sends a report on syn sent state.
func (d *Datapath) sendOriginPingReport(
	sessionID,
	agentVersion,
	flowTuple string,
	context *pucontext.PUContext,
	pingType claimsheader.PingType,
	payloadSize,
	request int,
) {
	d.sendPingReport(
		sessionID,
		agentVersion,
		flowTuple,
		"",
		context.ManagementID(),
		context.ManagementNamespace(),
		"",
		"",
		pingType,
		collector.Origin,
		payloadSize,
		request,
	)
}

// sendOriginPingReport sends a report on synack recv state.
func (d *Datapath) sendReplyPingReport(
	ci *customIdentity,
	tcpConn *connection.TCPConnection,
	context *pucontext.PUContext,
	rtt string,
	payloadSize int,
) {
	d.sendPingReport(
		tcpConn.PingConfig.SessionID,
		ci.AgentVersion,
		ci.FlowTuple,
		rtt,
		context.ManagementID(),
		context.ManagementNamespace(),
		ci.TransmitterID,
		ci.TransmitterNamespace,
		tcpConn.PingConfig.Type,
		collector.Reply,
		payloadSize,
		tcpConn.PingConfig.Request,
	)
}

func (d *Datapath) sendPingReport(
	sessionID,
	agentVersion,
	flowTuple,
	rtt,
	srcID,
	srcNS,
	dstID,
	dstNS string,
	PingType claimsheader.PingType,
	stage collector.Stage,
	payloadSize,
	request int,
) {

	report := &collector.PingReport{
		AgentVersion:         agentVersion,
		FlowTuple:            flowTuple,
		Latency:              rtt,
		PayloadSize:          payloadSize,
		Type:                 PingType,
		Stage:                stage,
		SourceID:             srcID,
		SourceNamespace:      srcNS,
		DestinationNamespace: dstNS,
		DestinationID:        dstID,
		SessionID:            sessionID,
		Protocol:             tpacket.IPProtocolTCP,
		ServiceType:          "L3",
		Request:              request,
	}

	d.collector.CollectPingEvent(report)
}

// customIdentity holds data that needs to be passed on wire.
type customIdentity struct {
	AgentVersion         string
	TransmitterID        string
	TransmitterNamespace string
	FlowTuple            string
}

// encode returns bytes of c, returns error on nil.
func (c *customIdentity) encode() ([]byte, error) {

	if c == nil {
		return nil, fmt.Errorf("cannot encode nil custom identity")
	}

	b, err := msgpack.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("unable to encode custom identity: %v", err)
	}

	return b, nil
}

// decode returns customIdentity, returns error on nil.
func (c *customIdentity) decode(b []byte) error {

	if c == nil {
		return fmt.Errorf("cannot decode nil custom identity")
	}

	if err := msgpack.Unmarshal(b, c); err != nil {
		return fmt.Errorf("unable to decode custom identity: %v", err)
	}

	return nil
}
