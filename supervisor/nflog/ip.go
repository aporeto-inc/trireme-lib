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
	LengthOffset int
	SrcOffset    int
	DstOffset    int
	HeaderSize   int
	AddrLen      int
}

// Src TODO
func (i *IPPacketInfo) Src(packet []byte) net.IP {
	return net.IP(packet[i.SrcOffset : i.SrcOffset+i.AddrLen])
}

// Dst TODO
func (i *IPPacketInfo) Dst(packet []byte) net.IP {
	return net.IP(packet[i.DstOffset : i.DstOffset+i.AddrLen])
}

// Length TODO
func (i *IPPacketInfo) Length(packet []byte) int {
	return int(packet[i.LengthOffset])<<8 + int(packet[i.LengthOffset+1])
}

// IP4Packet TODO
var IP4Packet = &IPPacketInfo{
	// 20 bytes IPv4 Header - http://en.wikipedia.org/wiki/IPv4
	LengthOffset: 2,
	SrcOffset:    12,
	DstOffset:    16,
	HeaderSize:   20,
	AddrLen:      4,
}

// IP6Packet TODO
var IP6Packet = &IPPacketInfo{
	// 40 bytes IPv6 Header - http://en.wikipedia.org/wiki/IPv6_packet
	LengthOffset: 4,
	SrcOffset:    8,
	DstOffset:    24,
	HeaderSize:   40,
	AddrLen:      16,
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
