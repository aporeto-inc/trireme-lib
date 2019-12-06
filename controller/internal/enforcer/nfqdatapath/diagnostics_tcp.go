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
	"go.aporeto.io/trireme-lib/utils/netinterfaces"
	"go.uber.org/zap"
)

const (
	agentVersionKey = "agentVersion"
	flowTupleKey    = "flowTuple"
)

func (d *Datapath) initiateDiagnosticAppSynPacket(ctx context.Context, contextID string, diagnosticsInfo *policy.DiagnosticsConfig) error {

	zap.L().Info("Initiating connection")

	if diagnosticsInfo == nil {
		return nil
	}

	srcIP, err := getSrcIP()
	if err != nil {
		return fmt.Errorf("unable to get source ip: %v", err)
	}

	dstIP := net.ParseIP(diagnosticsInfo.IP)

	conn, err := dialIP(srcIP, dstIP)
	if err != nil {
		return fmt.Errorf("unable to dialIP on app syn: %v", err)
	}
	defer conn.Close()

	srcPort, err := freeport.GetFreePort()
	if err != nil {
		return fmt.Errorf("unable to get free source port: %v", err)
	}

	item, err := d.puFromContextID.Get(contextID)
	if err != nil {
		return fmt.Errorf("unable to find contextID %s in cache: %v", contextID, err)
	}

	context := item.(*pucontext.PUContext)

	tcpConn := connection.NewTCPConnection(context, nil)

	claimsHeader := claimsheader.NewClaimsHeader(
		claimsheader.OptionDiagnosticType(diagnosticsInfo.Type),
	)

	tcpData, err := d.tokenAccessor.CreateSynPacketToken(context, &tcpConn.Auth, claimsHeader)
	if err != nil {
		return fmt.Errorf("unable to create syn token: %v", err)
	}

	for _, port := range diagnosticsInfo.Ports {

		dstPort, err := strconv.Atoi(port)
		if err != nil {
			continue
		}

		p, err := constructSynPacket(srcIP, dstIP, uint16(srcPort), uint16(dstPort), tcpData, 0)
		if err != nil {
			return fmt.Errorf("unable to construct syn packet: %v", err)
		}

		tcpConn.StartTime = time.Now()
		tcpConn.DiagnosticType = diagnosticsInfo.Type

		if err := write(conn, p); err != nil {
			return fmt.Errorf("unable to send syn packet: %v", err)
		}

		d.sendOriginDiagnosticReport(
			flowTuple(
				tpacket.PacketTypeApplication,
				srcIP.String(),
				diagnosticsInfo.IP,
				uint16(srcPort),
				uint16(dstPort),
				6,
			),
			context.ManagementID(),
			context.ManagementNamespace(),
			diagnosticsInfo.Type.String(),
			collector.Origin,
			len(tcpData),
		)

		// Only cache it on syn.
		d.diagnosticConnectionCache.AddOrUpdate(key(tpacket.PacketTypeApplication, srcIP.String(), diagnosticsInfo.IP, uint16(srcPort), uint16(dstPort)), tcpConn)
	}

	return nil
}

func (d *Datapath) processDiagnosticNetSynPacket(context *pucontext.PUContext, tcpConn *connection.TCPConnection, tcpPacket *tpacket.Packet, claims *tokens.ConnectionClaims) error {
	zap.L().Info("DIAGNOSTIC NET SYN RECV")

	ch := claims.H.ToClaimsHeader()
	tcpConn.DiagnosticType = ch.DiagnosticType()

	if ch.DiagnosticType() == claimsheader.DiagnosticTypeAporetoIdentityPassthrough {

		zap.L().Info("DIAGNOSTIC PACKET PT FROM APP")
		fmt.Println(tcpPacket.L4ReverseFlowHash())
		d.diagnosticConnectionCache.AddOrUpdate(tcpPacket.SourcePortHash(tpacket.PacketTypeNetwork), tcpConn)
		return nil
	}

	zap.L().Info("DIAGNOSTIC SYNACK PACKET SENT")

	conn, err := dialIP(tcpPacket.DestinationAddress(), tcpPacket.SourceAddress())
	if err != nil {
		return fmt.Errorf("unable to dialIP on net syn: %v", err)
	}
	defer conn.Close()

	var tcpData []byte

	// Add our data here.
	if ch.DiagnosticType() == claimsheader.DiagnosticTypeAporetoIdentityPassthrough {
		tcpData, err = encode(context.ManagementID(), d.agentVersion.String(), flowTuple(tpacket.PacketTypeNetwork, tcpPacket.SourceAddress().String(), tcpPacket.DestinationAddress().String(), tcpPacket.SourcePort(), tcpPacket.DestPort(), 6))
		if err != nil {
			return fmt.Errorf("unable to create synack token: %v", err)
		}
	} else {
		tcpData, err = d.tokenAccessor.CreateSynAckPacketToken(context, &tcpConn.Auth, ch)
		if err != nil {
			return fmt.Errorf("unable to create synack token: %v", err)
		}
	}

	p, err := constructSynAckPacket(tcpPacket.DestinationAddress(), tcpPacket.SourceAddress(), tcpPacket.DestPort(), tcpPacket.SourcePort(), tcpData, 0)
	if err != nil {
		return fmt.Errorf("unable to construct synack packet: %v", err)
	}

	if err := write(conn, p); err != nil {
		return fmt.Errorf("unable to send synack packet: %v", err)
	}

	return nil
}

func (d *Datapath) processDiagnosticNetSynAckPacket(context *pucontext.PUContext, tcpConn *connection.TCPConnection, tcpPacket *tpacket.Packet, claims *tokens.ConnectionClaims, ext bool, custom bool) error {
	zap.L().Info("DIAGNOSTIC SYN ACK PACKET RECV")

	receiveTime := time.Now().Sub(tcpConn.StartTime)

	sendAck := func() error {

		zap.L().Info("DIAGNOSTIC PACKET ACK")

		conn, err := dialIP(tcpPacket.DestinationAddress(), tcpPacket.SourceAddress())
		if err != nil {
			return fmt.Errorf("unable to dialIP on net synack: %v", err)
		}
		defer conn.Close()

		p, err := constructAckPacket(tcpPacket.DestinationAddress(), tcpPacket.SourceAddress(), tcpPacket.DestPort(), tcpPacket.SourcePort(), tcpPacket.Seq())
		if err != nil {
			return fmt.Errorf("unable to construct ack packet: %v", err)
		}

		if err := write(conn, p); err != nil {
			return fmt.Errorf("unable to send ack packet: %v", err)
		}

		return nil
	}

	if ext {
		return sendAck()
	}

	if custom {

		data, err := decode(tcpPacket.ReadTCPData())
		if err != nil {
			return err
		}

		fmt.Println("DATA", data)

		av, _ := data[agentVersionKey]
		flowTuple, _ := data[flowTupleKey]
		txtLabel, _ := data[enforcerconstants.TransmitterLabel]

		ci := &customIdentity{
			agentVersion: av.(string),
			dstID:        txtLabel.(string),
			flowTuple:    flowTuple.(string),
		}

		d.sendReplyDiagnosticReport(ci, tcpConn.DiagnosticType.String(), receiveTime.String(), context.ManagementID(), context.ManagementNamespace(), collector.Reply, len(tcpPacket.ReadTCPData()))

		return nil
	}

	ch := claims.H.ToClaimsHeader()
	if tcpConn.DiagnosticType == claimsheader.DiagnosticTypeAporetoIdentityPassthrough {
		tcpConn.DiagnosticType = claimsheader.DiagnosticTypeAporetoIdentity
	}

	d.sendReplyDiagnosticReport(&customIdentity{}, ch.DiagnosticType().String(), receiveTime.String(), context.ManagementID(), context.ManagementNamespace(), collector.Reply, len(tcpPacket.GetTCPData()))

	if ch.DiagnosticType() == claimsheader.DiagnosticTypeAporetoIdentityPassthrough {

		return sendAck()
	}

	return nil
}

func (d *Datapath) sendOriginDiagnosticReport(flowTuple, srcID, namespace, diagnosticType string, stage collector.Stage, payloadSize int) {

	d.sendDiagnosticReport(d.agentVersion.String(), flowTuple, "", srcID, "", namespace, diagnosticType, stage, payloadSize)
}

func (d *Datapath) sendReplyDiagnosticReport(ci *customIdentity, rtt, srcID, namespace, dtype string, stage collector.Stage, payloadSize int) {

	d.sendDiagnosticReport(ci.agentVersion, ci.flowTuple, rtt, srcID, ci.agentVersion, namespace, dtype, stage, payloadSize)
}

type customIdentity struct {
	agentVersion string
	dstID        string
	flowTuple    string
}

func (d *Datapath) sendDiagnosticReport(agentVersion, flowTuple, rtt, srcID, dstID, namespace, diagnosticType string, stage collector.Stage, payloadSize int) {

	record := &collector.DiagnosticsReport{
		AgentVersion:  agentVersion,
		FlowTuple:     flowTuple,
		Latency:       rtt,
		PayloadSize:   payloadSize,
		Type:          diagnosticType,
		Stage:         stage,
		SourceID:      srcID,
		DestinationID: dstID,
		Namespace:     namespace,
	}

	d.collector.CollectDiagnosticsEvent(record)
}

func (d *Datapath) processDiagnosticAppSynAckPacket(context *pucontext.PUContext, tcpConn *connection.TCPConnection, tcpPacket *tpacket.Packet, claimsHeader *claimsheader.ClaimsHeader) ([]byte, error) {

	claimsHeader.SetDiagnosticType(tcpConn.DiagnosticType)

	// d.updateCustomIdentity(
	// 	context,
	// 	packet.SourceAddress().String(),
	// 	packet.DestinationAddress().String(),
	// 	packet.SourcePort(),
	// 	packet.DestPort(),
	// 	6,
	// )

	tuple := flowTuple(tpacket.PacketTypeNetwork, tcpPacket.SourceAddress().String(), tcpPacket.DestinationAddress().String(), tcpPacket.SourcePort(), tcpPacket.DestPort(), 6)
	return encode(context.ManagementID(), d.agentVersion.String(), tuple)
}

func constructSynPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, tcpData []byte, tseq uint32) ([]byte, error) {

	options := []tcp.Option{
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

	offset := uint8(7)

	return constructPacket(srcIP, dstIP, srcPort, dstPort, tcp.Syn, tcpData, tseq, options, offset)
}

func constructSynAckPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, tcpData []byte, tseq uint32) ([]byte, error) {

	options := []tcp.Option{
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

	offset := uint8(7)

	return constructPacket(srcIP, dstIP, srcPort, dstPort, tcp.Syn|tcp.Ack, tcpData, tseq, options, offset)
}

func constructAckPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, tseq uint32) ([]byte, error) {

	options := []tcp.Option{
		{
			Type: tcp.MSS,
			Len:  4,
			Data: []byte{0x05, 0x8C},
		},
	}

	offset := uint8(6)

	return constructPacket(srcIP, dstIP, srcPort, dstPort, tcp.Ack, nil, tseq, options, offset)
}

func constructPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, flag tcp.Flags, tcpData []byte, tseq uint32, options []tcp.Option, offset uint8) ([]byte, error) {

	ipPacket := ipv4.Make()
	ipPacket.SrcAddr = srcIP
	ipPacket.DstAddr = dstIP
	ipPacket.Protocol = ipv4.TCP

	var ack uint32 = 0
	if flag == tcp.Ack {
		ack = tseq + uint32(1)
	}

	tcpPacket := tcp.Make()
	tcpPacket.SrcPort = srcPort
	tcpPacket.DstPort = dstPort
	tcpPacket.Flags = flag
	tcpPacket.Seq = rand.Uint32()
	tcpPacket.Ack = ack
	tcpPacket.WindowSize = 0xAAAA
	tcpPacket.Options = options
	tcpPacket.DataOff = offset

	payload := raw.Make()
	payload.Data = tcpData

	tcpPacket.SetPayload(payload)
	ipPacket.SetPayload(tcpPacket)

	buf, err := layers.Pack(tcpPacket, payload)
	if err != nil {
		return nil, fmt.Errorf("unable to encode packet to wire format: %v", err)
	}

	return buf, nil
}

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

func dialIP(srcIP, dstIP net.IP) (net.Conn, error) {

	d := net.Dialer{
		Timeout:   5 * time.Second,
		LocalAddr: &net.IPAddr{IP: srcIP},
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 0x24, 0x40); err != nil {
					zap.L().Error("unable to assign mark", zap.Error(err))
				}
			})
		},
	}

	return d.Dial("ip4:tcp", dstIP.String())
}

func key(stage uint64, srcIP, dstIP string, srcPort, dstPort uint16) string {
	if stage == tpacket.PacketTypeNetwork {
		return dstIP + ":" + strconv.Itoa(int(dstPort))
	}

	return srcIP + ":" + strconv.Itoa(int(srcPort))
}

func flowTuple(stage uint64, srcIP, dstIP string, srcPort, dstPort uint16, proto int) string {
	if stage == tpacket.PacketTypeNetwork {
		return fmt.Sprintf("%s:%s:%d:%d:%d", dstIP, srcIP, dstPort, srcPort, proto)
	}

	return fmt.Sprintf("%s:%s:%d:%d:%d", srcIP, dstIP, srcPort, dstPort, proto)
}

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

func encode(dstID, agentVersion, flowTuple string) ([]byte, error) {

	data := map[string]interface{}{
		agentVersionKey:                    agentVersion,
		enforcerconstants.TransmitterLabel: dstID,
		flowTupleKey:                       flowTuple,
	}

	b, err := msgpack.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("unable to encode custom identities: %v", err)
	}

	return b, nil
}

func decode(b []byte) (map[string]interface{}, error) {

	data := map[string]interface{}{}

	if err := msgpack.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("unable to decode custom identities: %v", err)
	}

	return data, nil
}
