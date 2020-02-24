// +build windows

package nfqdatapath

import (
	"fmt"
	"math/rand"
	"net"
	"syscall"
	"unsafe"

	"github.com/aporeto-inc/gopkt/layers"
	"github.com/aporeto-inc/gopkt/packet/ipv4"
	"github.com/aporeto-inc/gopkt/packet/raw"
	"github.com/aporeto-inc/gopkt/packet/tcp"
	enforcerconstants "go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
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

func IPtoUint32Array(ip net.IP) [4]uint32 {
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
		LocalAddr:  IPtoUint32Array(diagConn.SourceIp),
		RemoteAddr: IPtoUint32Array(diagConn.DestIp),
		PacketSize: uint32(len(data)),
	}

	dllRet, _, err := frontman.PacketFilterForwardProc.Call(uintptr(unsafe.Pointer(&packetInfo)), uintptr(unsafe.Pointer(&data[0])))
	if dllRet == 0 && err != nil {
		return err
	}
	return nil
}

func (diagConn *diagnosticsConnection) constructPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, flag tcp.Flags, tcpData []byte) ([]byte, error) {

	ignoreFlow := uint8(1)
	if flag == tcp.Syn {
		// When sending the Syn packet, we want the other packets to come back up to NFQ
		ignoreFlow = 0
	}

	diagConn.IgnoreFlow = ignoreFlow
	diagConn.SourceIp = srcIP
	diagConn.DestIp = dstIP
	diagConn.SourcePort = srcPort
	diagConn.DestPort = dstPort

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

	tcpPacket.SetPayload(payload)  // nolint:errcheck
	ipPacket.SetPayload(tcpPacket) // nolint:errcheck

	// pack the layers together.
	buf, err := layers.Pack(ipPacket, tcpPacket, payload)
	if err != nil {
		return nil, fmt.Errorf("unable to encode packet to wire format: %v", err)
	}

	return buf, nil
}
