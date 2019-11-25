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
	"github.com/ghedo/go.pkt/packet/raw"
	"github.com/ghedo/go.pkt/packet/tcp"
	"github.com/phayes/freeport"
	enforcerconstants "go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	tpacket "go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/netinterfaces"
	"go.uber.org/zap"
)

func (d *Datapath) initiateDiagnosticSynPacket(ctx context.Context, contextID string, diagnosticsInfo *policy.DiagnosticsInfo) error {

	zap.L().Info("Initiating connection")

	if diagnosticsInfo == nil {
		return nil
	}

	srcIP, err := getSrcIP()
	if err != nil {
		return err
	}

	conn, err := dialIP(srcIP, net.ParseIP(diagnosticsInfo.IP))
	if err != nil {
		return err
	}
	defer conn.Close()

	srcPort, err := freeport.GetFreePort()
	if err != nil {
		return err
	}

	item, err := d.puFromContextID.Get(contextID)
	if err != nil {
		return pucontext.PuContextError(pucontext.ErrContextIDNotFound, "")
	}

	context := item.(*pucontext.PUContext)

	tcpConn := connection.NewTCPConnection(context, nil)

	claimsHeader := claimsheader.NewClaimsHeader(
		claimsheader.OptionDiagnosticType(claimsheader.DiagnosticTypeToken),
	)

	tcpData, err := d.tokenAccessor.CreateSynPacketToken(context, &tcpConn.Auth, claimsHeader)
	if err != nil {
		return err
	}

	dstPort, _ := strconv.Atoi(diagnosticsInfo.Ports[0])

	p, err := d.constructPacket(uint16(srcPort), uint16(dstPort), tcp.Syn, tcpData)
	if err != nil {
		return err
	}

	tcpConn.StartTime = time.Now()

	n, err := conn.Write(p)
	if err != nil {
		return err
	}

	if n != len(p) {
		return fmt.Errorf("partial data written")
	}

	// Set the state indicating that we send out a Syn packet
	tcpConn.SetState(connection.TCPSynSend)

	d.diagnosticConnectionCache.AddOrUpdate(SourcePortHash(tpacket.PacketTypeApplication, srcIP.String(), diagnosticsInfo.IP, uint16(srcPort), uint16(dstPort)), tcpConn)

	return nil
}

func (d *Datapath) replyDiagnosticSynAckPacket(context *pucontext.PUContext, tcpPacket *tpacket.Packet, claimsHeader *claimsheader.ClaimsHeader) error {
	zap.L().Info("DIAGNOSTIC SYNACK PACKET SENT")

	conn, err := dialIP(tcpPacket.DestinationAddress(), tcpPacket.SourceAddress())
	if err != nil {
		return err
	}
	defer conn.Close()

	tcpConn := connection.NewTCPConnection(context, nil)

	ch := claimsheader.NewClaimsHeader(
		claimsheader.OptionDiagnosticType(claimsHeader.DiagnosticType()),
	)

	// never returns error
	tcpData, err := d.tokenAccessor.CreateSynAckPacketToken(context, &tcpConn.Auth, ch)
	if err != nil {
		return err
	}

	p, err := d.constructPacket(tcpPacket.DestPort(), tcpPacket.SourcePort(), tcp.Syn|tcp.Ack, tcpData)
	if err != nil {
		return err
	}

	_, err = conn.Write(p)
	if err != nil {
		return err
	}

	return nil
}

func (d *Datapath) processDiagnosticNetSynAckPacket(tcpPacket *tpacket.Packet, claimsHeader *claimsheader.ClaimsHeader) error {
	zap.L().Info("DIAGNOSTIC SYN ACK PACKET RECV")

	item, err := d.diagnosticConnectionCache.GetReset(SourcePortHash(tpacket.PacketTypeNetwork, tcpPacket.SourceAddress().String(), tcpPacket.DestinationAddress().String(), tcpPacket.SourcePort(), tcpPacket.DestPort()), 0)
	if err != nil {
		return err
	}

	conn := item.(*connection.TCPConnection)

	receiveTime := time.Now().Sub(conn.StartTime)

	fmt.Println("rtt", receiveTime)

	return nil
}

func (d *Datapath) constructPacket(srcPort, dstPort uint16, flag tcp.Flags, tcpData []byte) ([]byte, error) {

	tcpPacket := tcp.Make()
	tcpPacket.SrcPort = srcPort
	tcpPacket.DstPort = dstPort
	tcpPacket.Flags = flag
	tcpPacket.Seq = rand.Uint32()
	tcpPacket.WindowSize = 0xAAAA
	tcpPacket.Options = []tcp.Option{
		tcp.Option{
			Type: tcp.MSS,
			Len:  4,
			Data: []byte{0x05, 0x8C},
		},
		tcp.Option{
			Type: 34, // tfo
			Len:  enforcerconstants.TCPAuthenticationOptionBaseLen,
			Data: make([]byte, 2),
		},
	}
	tcpPacket.DataOff = 5 + 2

	payload := raw.Make()
	payload.Data = tcpData

	buf, err := layers.Pack(tcpPacket, payload)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func getSrcIP() (net.IP, error) {

	ifaces, err := netinterfaces.GetInterfacesInfo()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if len(iface.IPs) == 0 {
			return nil, fmt.Errorf("ip missing in interface: %v", iface.Name)
		}

		return iface.IPs[0], nil
	}

	return nil, fmt.Errorf("unable to get source ip")
}

func dialIP(srcIP, dstIP net.IP) (net.Conn, error) {

	d := net.Dialer{
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

func SourcePortHash(stage uint64, srcIP, dstIP string, srcPort, dstPort uint16) string {
	if stage == tpacket.PacketTypeNetwork {
		return dstIP + ":" + strconv.Itoa(int(dstPort))
	}

	return srcIP + ":" + strconv.Itoa(int(srcPort))
}
