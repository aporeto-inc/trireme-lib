// +build windows

package nfqdatapath

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/ghedo/go.pkt/layers"
	gpacket "github.com/ghedo/go.pkt/packet"
	"github.com/ghedo/go.pkt/packet/ipv4"
	"github.com/ghedo/go.pkt/packet/tcp"
	"github.com/pkg/errors"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/utils/frontman"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

func adjustConntrack(mode constants.ModeType) {
}

func (d *Datapath) reverseFlow(pkt *packet.Packet) error {
	windata, ok := pkt.PlatformMetadata.(*afinetrawsocket.WindowPlatformMetadata)
	if !ok {
		return errors.New("no WindowPlatformMetadata for reverseFlow")
	}

	address := windata.PacketInfo.RemoteAddr
	windata.PacketInfo.RemoteAddr = windata.PacketInfo.LocalAddr
	windata.PacketInfo.LocalAddr = address

	port := windata.PacketInfo.RemotePort
	windata.PacketInfo.RemotePort = windata.PacketInfo.LocalPort
	windata.PacketInfo.LocalPort = port

	return nil
}

func (d *Datapath) drop(pkt *packet.Packet) error {
	windata, ok := pkt.PlatformMetadata.(*afinetrawsocket.WindowPlatformMetadata)
	if !ok {
		return errors.New("no WindowPlatformMetadata for drop")
	}
	windata.Drop = true
	return nil
}

func (d *Datapath) setMark(pkt *packet.Packet, mark uint32) error {
	windata, ok := pkt.PlatformMetadata.(*afinetrawsocket.WindowPlatformMetadata)
	if !ok {
		return errors.New("no WindowPlatformMetadata for setMark")
	}
	windata.SetMark = mark
	return nil
}

// ignoreFlow is for Windows, because we need a way to explicitly notify of an 'ignore flow' condition,
// without going through flowtracking, to be called synchronously in datapath processing
func (d *Datapath) ignoreFlow(pkt *packet.Packet) error {
	windata, ok := pkt.PlatformMetadata.(*afinetrawsocket.WindowPlatformMetadata)
	if !ok {
		return errors.New("no WindowPlatformMetadata for ignoreFlow")
	}
	windata.IgnoreFlow = true
	return nil
}

// dropFlow will tell the windows driver to continue to drop packets for this flow.
func (d *Datapath) dropFlow(pkt *packet.Packet) error {
	windata, ok := pkt.PlatformMetadata.(*afinetrawsocket.WindowPlatformMetadata)
	if !ok {
		return errors.New("no WindowPlatformMetadata for dropFlow")
	}
	windata.DropFlow = true
	return nil
}

// setFlowState will not send the packet but will tell the Windows driver to either accept or drop the flow.
func (d *Datapath) setFlowState(pkt *packet.Packet, accepted bool) error {
	windata, ok := pkt.PlatformMetadata.(*afinetrawsocket.WindowPlatformMetadata)
	if !ok {
		return errors.New("no WindowPlatformMetadata for setFlowState")
	}

	buf := pkt.GetBuffer(0)
	packetInfo := windata.PacketInfo
	packetInfo.NewPacket = 1
	packetInfo.Drop = 1
	packetInfo.IgnoreFlow = 0
	packetInfo.DropFlow = 0
	if accepted {
		packetInfo.IgnoreFlow = 1
	} else {
		packetInfo.DropFlow = 1
	}
	packetInfo.PacketSize = uint32(len(buf))
	if err := frontman.Wrapper.PacketFilterForward(&packetInfo, buf); err != nil {
		return err
	}
	return nil
}

func (d *Datapath) startInterceptors(ctx context.Context) {
	err := d.startFrontmanPacketFilter(ctx, d.nflogger)
	if err != nil {
		zap.L().Fatal("Unable to initialize windows packet proxy", zap.Error(err))
	}
}

type pingConn struct {
	SourceIP   net.IP
	DestIP     net.IP
	SourcePort uint16
	DestPort   uint16
}

func dialIP(srcIP, dstIP net.IP) (PingConn, error) {
	return &pingConn{}, nil
}

// Close not implemented.
func (p *pingConn) Close() error {
	return nil
}

// Write sends the packet to network.
func (p *pingConn) Write(data []byte) (int, error) {

	ipv4 := uint8(0)
	if len(p.SourceIP) == net.IPv4len {
		ipv4 = 1
	}

	packetInfo := frontman.PacketInfo{
		Ipv4:             ipv4,
		Protocol:         windows.IPPROTO_TCP,
		Outbound:         1,
		NewPacket:        1,
		NoPidMatchOnFlow: 1,
		LocalPort:        p.SourcePort,
		RemotePort:       p.DestPort,
		LocalAddr:        convertToDriverFormat(p.SourceIP),
		RemoteAddr:       convertToDriverFormat(p.DestIP),
		PacketSize:       uint32(len(data)),
	}

	dllRet, err := frontman.Driver.PacketFilterForward(uintptr(unsafe.Pointer(&packetInfo)), uintptr(unsafe.Pointer(&data[0])))
	if dllRet == 0 && err != nil {
		return 0, err
	}

	return len(data), nil
}

// ConstructWirePacket returns IP packet with given TCP and payload in wire format.
func (p *pingConn) ConstructWirePacket(srcIP, dstIP net.IP, transport gpacket.Packet, payload gpacket.Packet) ([]byte, error) {

	ipPacket := ipv4.Make()
	ipPacket.SrcAddr = srcIP
	ipPacket.DstAddr = dstIP
	ipPacket.Protocol = ipv4.TCP

	// pack the layers together.
	buf, err := layers.Pack(ipPacket, transport, payload)
	if err != nil {
		return nil, fmt.Errorf("unable to encode packet to wire format: %v", err)
	}

	tcpPacket := transport.(*tcp.Packet)

	p.SourceIP = srcIP
	p.DestIP = dstIP
	p.SourcePort = tcpPacket.SrcPort
	p.DestPort = tcpPacket.DstPort

	return buf, nil
}

func bindRandomPort(tcpConn *connection.TCPConnection) (uint16, error) {

	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		return 0, fmt.Errorf("unable to open socket, fd: %d : %s", fd, err)
	}

	addr := windows.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], net.ParseIP("127.0.0.1").To4())
	if err = windows.Bind(fd, &addr); err != nil {
		windows.CloseHandle(fd) // nolint: errcheck
		return 0, fmt.Errorf("unable to bind socket: %s", err)
	}

	sockAddr, err := windows.Getsockname(fd)
	if err != nil {
		windows.CloseHandle(fd) // nolint: errcheck
		return 0, fmt.Errorf("unable to get socket address: %s", err)
	}

	ip4Addr, ok := sockAddr.(*windows.SockaddrInet4)
	if !ok {
		windows.CloseHandle(fd) // nolint: errcheck
		return 0, fmt.Errorf("invalid socket address: %T", sockAddr)
	}

	tcpConn.PingConfig.SetSocketFd(uintptr(fd))
	return uint16(ip4Addr.Port), nil
}

func closeRandomPort(tcpConn *connection.TCPConnection) error {

	fd := tcpConn.PingConfig.SocketFd()
	tcpConn.PingConfig.SetSocketClosed(true)

	return windows.CloseHandle(windows.Handle(fd))
}

func convertToDriverFormat(ip net.IP) [4]uint32 {
	var addr [4]uint32
	byteAddr := (*[16]byte)(unsafe.Pointer(&addr))
	copy(byteAddr[:], ip)
	return addr
}

func isAddrInUseErrno(errNo syscall.Errno) bool {
	return errNo == windows.WSAEADDRINUSE
}
