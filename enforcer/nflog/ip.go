// Parse and account IP packets

package nflog

import (
	"fmt"
	"net"
)

// How to read the IP version number from an IP packet
const (
	IPVersion      = 0
	IPVersionShift = 4
	IPVersionMask  = 0x0f
)

// IPPacketInfo TODO
type IPPacketInfo struct {
	LengthOffset   int
	SrcOffset      int
	SrcPortOffset  int
	DstOffset      int
	DstPortOffset  int
	HeaderSize     int
	AddrLen        int
	PortLen        int
	CopyPacketSize int
}

// Src returns the source IP address
func (i *IPPacketInfo) Src(packet []byte) net.IP {
	return net.IP(packet[i.SrcOffset : i.SrcOffset+i.AddrLen])
}

// SrcPort returns the source port
func (i *IPPacketInfo) SrcPort(packet []byte) int {
	return int(packet[i.SrcPortOffset])<<8 + int(packet[i.SrcPortOffset+1])
}

// Dst returns the destination IP address
func (i *IPPacketInfo) Dst(packet []byte) net.IP {
	return net.IP(packet[i.DstOffset : i.DstOffset+i.AddrLen])
}

// DstPort returns the destination port
func (i *IPPacketInfo) DstPort(packet []byte) int {
	return int(packet[i.DstPortOffset])<<8 + int(packet[i.DstPortOffset+1])
}

// Length returns the entire packet length
func (i *IPPacketInfo) Length(packet []byte) int {
	return int(packet[i.LengthOffset])<<8 + int(packet[i.LengthOffset+1])
}

// IPHeaderLength returns the IP header length (IHL)
func (i *IPPacketInfo) IPHeaderLength(packet []byte) int {
	return int(packet[0]&0x0f) * 4
}

// IP4Packet TODO
var IP4Packet = &IPPacketInfo{
	// 20 bytes IPv4 Header - http://en.wikipedia.org/wiki/IPv4
	// + 4 bytes for source and destination port
	LengthOffset:   2,
	SrcOffset:      12,
	SrcPortOffset:  20,
	DstOffset:      16,
	DstPortOffset:  22,
	HeaderSize:     20,
	AddrLen:        4,
	PortLen:        2,
	CopyPacketSize: 24,
}

// IP6Packet TODO
var IP6Packet = &IPPacketInfo{
	// 40 bytes IPv6 Header - http://en.wikipedia.org/wiki/IPv6_packet
	// + 4 bytes for source and destination port
	LengthOffset:   4,
	SrcOffset:      8,
	SrcPortOffset:  40,
	DstOffset:      24,
	DstPortOffset:  42,
	HeaderSize:     40,
	AddrLen:        16,
	PortLen:        2,
	CopyPacketSize: 44,
}

// IPDirection TODO
type IPDirection bool

func (sod IPDirection) String() string {
	if sod {
		return "Source"
	}
	return "Dest"
}

// TODO
const (
	IPSource = IPDirection(true)
	IPDest   = IPDirection(false)
)

// Check it implements the interface
var _ fmt.Stringer = IPDirection(false)
