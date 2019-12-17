package nfqdatapath

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/ghedo/go.pkt/layers"
	"github.com/ghedo/go.pkt/packet/ipv4"
	"github.com/ghedo/go.pkt/packet/raw"
	"github.com/ghedo/go.pkt/packet/tcp"
	"github.com/jackpal/gateway"
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
	"go.aporeto.io/trireme-lib/utils/netinterfaces"
	"go.uber.org/zap"
)

const (
	agentVersionKey = "agentVersion"
	flowTupleKey    = "flowTuple"
)

func (d *Datapath) initiateDiagnosticAppSynPacket(ctx context.Context, contextID string, pingConfig *policy.PingConfig) error {

	zap.L().Debug("Initiating diagnostics (syn)")

	if pingConfig == nil {
		return nil
	}

	srcIP, err := getSrcIP()
	if err != nil {
		return fmt.Errorf("unable to get source ip: %v", err)
	}

	conn, err := dial(srcIP, pingConfig.IP)
	if err != nil {
		return fmt.Errorf("unable to dial on app syn: %v", err)
	}
	defer conn.Close()

	item, err := d.puFromContextID.Get(contextID)
	if err != nil {
		return fmt.Errorf("unable to find contextID %s in cache: %v", contextID, err)
	}

	// NOTE: This never fails
	context := item.(*pucontext.PUContext)

	for i := 1; i <= pingConfig.Requests; i++ {
		if err := d.sendSynPacket(context, pingConfig, conn, srcIP, i); err != nil {
			return err
		}
	}

	return nil
}

// sendSynPacket sends tcp syn packet to the socket. It also dispatches a report.
func (d *Datapath) sendSynPacket(context *pucontext.PUContext, pingConfig *policy.PingConfig, conn net.Conn, srcIP net.IP, request int) error {

	for _, ports := range pingConfig.Ports {
		for dstPort := ports.Min; dstPort <= ports.Max; dstPort++ {

			tcpConn := connection.NewTCPConnection(context, nil)

			claimsHeader := claimsheader.NewClaimsHeader(
				claimsheader.OptionPingType(pingConfig.Type),
			)

			tcpData, err := d.tokenAccessor.CreateSynPacketToken(context, &tcpConn.Auth, claimsHeader)
			if err != nil {
				return fmt.Errorf("unable to create syn token: %v", err)
			}

			srcPort, err := freeport.GetFreePort()
			if err != nil {
				return fmt.Errorf("unable to get free source port: %v", err)
			}

			p, err := constructTCPPacket(srcIP, net.ParseIP(pingConfig.IP), uint16(srcPort), dstPort, tcp.Syn, tcpData)
			if err != nil {
				return fmt.Errorf("unable to construct syn packet: %v", err)
			}

			sessionID, err := crypto.GenerateRandomString(20)
			if err != nil {
				return err
			}

			tcpConn.PingConfig = &connection.PingConfig{
				StartTime: time.Now(),
				Type:      pingConfig.Type,
				SessionID: sessionID,
				Request:   request,
			}

			if err := write(conn, p); err != nil {
				return fmt.Errorf("unable to send syn packet: %v", err)
			}

			agentVersion := ""
			ftuple := ""
			if pingConfig.Type == claimsheader.PingTypeCustomIdentity {
				agentVersion = d.agentVersion.String()
				ftuple = flowTuple(
					tpacket.PacketTypeApplication,
					srcIP.String(),
					pingConfig.IP,
					uint16(srcPort),
					dstPort,
				)
			}

			d.sendOriginPingReport(
				sessionID,
				agentVersion,
				ftuple,
				context,
				pingConfig.Type,
				len(tcpData),
				request,
			)

			tcpConn.SetState(connection.TCPSynSend)

			d.diagnosticConnectionCache.AddOrUpdate(
				flowTuple(tpacket.PacketTypeApplication, srcIP.String(), pingConfig.IP, uint16(srcPort), dstPort),
				tcpConn,
			)
		}
	}

	return nil
}

// processDiagnosticNetSynPacket should only be called when the packet is recognized as a diagnostic syn packet.
func (d *Datapath) processDiagnosticNetSynPacket(
	context *pucontext.PUContext,
	tcpConn *connection.TCPConnection,
	tcpPacket *tpacket.Packet,
	claims *tokens.ConnectionClaims,
) error {
	zap.L().Debug("Processing diagnostic network syn packet")

	ch := claims.H.ToClaimsHeader()
	tcpConn.PingConfig.Type = ch.PingType()
	tcpConn.SetState(connection.TCPSynReceived)

	if ch.PingType() == claimsheader.PingTypeDefaultIdentityPassthrough {
		zap.L().Debug("Processing diagnostic network syn packet: defaultpassthrough")

		tcpConn.PingConfig.Passthrough = true
		d.diagnosticConnectionCache.AddOrUpdate(tcpPacket.L4ReverseFlowHash(), tcpConn)
		return nil
	}

	conn, err := dial(tcpPacket.DestinationAddress(), tcpPacket.SourceAddress().String())
	if err != nil {
		return fmt.Errorf("unable to dial on net syn: %v", err)
	}
	defer conn.Close()

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
			return fmt.Errorf("unable to create synack token: %v", err)
		}
	} else {
		tcpData, err = d.tokenAccessor.CreateSynAckPacketToken(context, &tcpConn.Auth, ch)
		if err != nil {
			return fmt.Errorf("unable to create synack token: %v", err)
		}
	}

	p, err := constructTCPPacket(
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

	if err := write(conn, p); err != nil {
		return fmt.Errorf("unable to send synack packet: %v", err)
	}

	tcpConn.SetState(connection.TCPSynAckSend)

	return nil
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
	zap.L().Debug("Processing diagnostic network synack packet")

	if tcpConn.GetState() == connection.TCPSynAckReceived {
		zap.L().Debug("Ignoring duplicate synack packets")
		return nil
	}

	receiveTime := time.Now().Sub(tcpConn.PingConfig.StartTime)
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
		return fmt.Errorf("unknown packet")
	}

	ci := &customIdentity{
		TransmitterID: txtID,
	}

	d.sendReplyPingReport(ci, tcpConn, context, receiveTime.String(), len(tcpPacket.ReadTCPData()))

	if tcpConn.PingConfig.Type == claimsheader.PingTypeDefaultIdentityPassthrough {
		zap.L().Debug("Processing diagnostic network synack packet: aporetopassthrough")
		tcpConn.PingConfig.Passthrough = true
		return nil
	}

	return nil
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

// constructTCPPacket constructs a valid tcp packet that can be sent on wire.
// checksum is calculated by the library. (https://github.com/ghedo/go.pkt/blob/master/packet/tcp/pkt.go#L181)
func constructTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, flag tcp.Flags, tcpData []byte) ([]byte, error) {

	// pseudo header.
	// NOTE: Used only for computing checksum.
	ipPacket := ipv4.Make()
	ipPacket.SrcAddr = srcIP
	ipPacket.DstAddr = dstIP
	ipPacket.Protocol = ipv4.TCP

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

	tcpPacket.SetPayload(payload)
	ipPacket.SetPayload(tcpPacket)

	// pack the layers together.
	buf, err := layers.Pack(tcpPacket, payload)
	if err != nil {
		return nil, fmt.Errorf("unable to encode packet to wire format: %v", err)
	}

	return buf, nil
}

// getSrcIP returns the gateway interface's IP.
func getSrcIP() (net.IP, error) {

	ip, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("unable to discover gateway ip: %v", err)
	}

	ifaces, err := netinterfaces.GetInterfacesInfo()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if len(iface.IPs) != len(iface.IPNets) {
			continue
		}

		for i, ipNet := range iface.IPNets {
			if !ipNet.Contains(ip) {
				continue
			}

			return iface.IPs[i], nil
		}
	}

	return nil, fmt.Errorf("no valid ip found")
}

// flowTuple returns the tuple based on the stage in format <sip:dip:spt:dpt>
func flowTuple(stage uint64, srcIP, dstIP string, srcPort, dstPort uint16) string {

	if stage == tpacket.PacketTypeNetwork {
		return fmt.Sprintf("%s:%s:%s:%s", dstIP, srcIP, strconv.Itoa(int(dstPort)), strconv.Itoa(int(srcPort)))
	}

	return fmt.Sprintf("%s:%s:%s:%s", srcIP, dstIP, strconv.Itoa(int(srcPort)), strconv.Itoa(int(dstPort)))
}

// dial opens raw ipv4:tcp socket and connects to the remote network.
func dial(srcIP net.IP, dstIP string) (net.Conn, error) {

	d := net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: -1,
		LocalAddr: &net.IPAddr{IP: srcIP},
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 0x24, 0x40); err != nil {
					zap.L().Error("unable to assign mark", zap.Error(err))
				}
			})
		},
	}

	return d.Dial("ip4:tcp", dstIP)
}

// write writes the given data to the conn.
func write(conn net.Conn, data []byte) error {

	n, err := conn.Write(data)
	if err != nil {
		return err
	}

	if n != len(data) {
		return fmt.Errorf("partial data written, total: %v, written: %v", len(data), n)
	}

	return nil
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
