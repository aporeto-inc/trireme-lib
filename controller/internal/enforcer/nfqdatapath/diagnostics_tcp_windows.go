// +build windows

package nfqdatapath

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/aporeto-inc/gopkt/layers"
	"github.com/aporeto-inc/gopkt/packet/ipv4"
	"github.com/aporeto-inc/gopkt/packet/raw"
	"github.com/aporeto-inc/gopkt/packet/tcp"

	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	//"github.com/aporeto-inc/gopkt/routing"
)

type diagnosticsConnection struct {
	SourceIp   net.IP
	DestIp     net.IP
	SourcePort uint16
	DestPort   uint16
	IgnoreFlow uint8
}

func createConnection(srcIP, dstIP net.IP) (*diagnosticsConnection, error) {
	return &diagnosticsConnection{}, nil
}

func (diagConn *diagnosticsConnection) Close() {
}

// converts IP address to the driver's format.
func convertToDriverFormat(ip net.IP) [4]uint32 {
	var addr [4]uint32
	byteAddr := (*[16]byte)(unsafe.Pointer(&addr))
	copy(byteAddr[:], ip)
	return addr
}

// write writes the given data to the conn.
func (diagConn *diagnosticsConnection) Write(data []byte) error {

	ipv4 := uint8(0)
	if len(diagConn.SourceIp) == net.IPv4len {
		ipv4 = 1
	}
	packetInfo := frontman.PacketInfo{
		Ipv4:       ipv4,
		Protocol:   syscall.IPPROTO_TCP,
		Outbound:   1,
		IgnoreFlow: diagConn.IgnoreFlow,
		LocalPort:  diagConn.SourcePort,
		RemotePort: diagConn.DestPort,
		LocalAddr:  convertToDriverFormat(diagConn.SourceIp),
		RemoteAddr: convertToDriverFormat(diagConn.DestIp),
		PacketSize: uint32(len(data)),
	}

	dllRet, _, err := frontman.PacketFilterForwardProc.Call(uintptr(unsafe.Pointer(&packetInfo)), uintptr(unsafe.Pointer(&data[0])))
	if dllRet == 0 && err != nil {
		return err
	}
	return nil
}

// constructWirePacket constructs a valid ip packet that the driver can be sent on wire.
func (diagConn *diagnosticsConnection) constructWirePacket(srcIP, dstIP net.IP, tcpPacket *tcp.Packet, payload *raw.Packet) ([]byte, error) {

	// ip packet created here to make it easier to support Ipv6 pings later.
	ipPacket := ipv4.Make()
	ipPacket.SrcAddr = srcIP
	ipPacket.DstAddr = dstIP
	ipPacket.Protocol = ipv4.TCP
	ipPacket.SetPayload(tcpPacket) // nolint:errcheck

	ignoreFlow := uint8(1)
	if tcpPacket.Flags == tcp.Syn {
		// When sending the Syn packet, we want the other packets to come back up to NFQ
		ignoreFlow = 0
	}

	diagConn.IgnoreFlow = ignoreFlow
	diagConn.SourceIp = srcIP
	diagConn.DestIp = dstIP
	diagConn.SourcePort = tcpPacket.SrcPort
	diagConn.DestPort = tcpPacket.DstPort

	// pack the layers together.
	buf, err := layers.Pack(ipPacket, tcpPacket, payload)
	if err != nil {
		return nil, fmt.Errorf("unable to encode packet to wire format: %v", err)
	}

	return buf, nil
}
