package packet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"

	"golang.org/x/net/ipv4"
)

// Helpher functions for the package, mainly for debugging and validation
// They are not used by the main package

// VerifyIPChecksum returns true if the IP header checksum is correct
// for this packet, false otherwise. Note that the checksum is not
// modified.
func (p *Packet) VerifyIPChecksum() bool {

	sum := p.computeIPChecksum()

	return sum == p.ipChecksum
}

// UpdateIPChecksum computes the IP header checksum and updates the
// packet with the value.
func (p *Packet) UpdateIPChecksum() {

	p.ipChecksum = p.computeIPChecksum()

	binary.BigEndian.PutUint16(p.Buffer[ipChecksumPos:ipChecksumPos+2], p.ipChecksum)
}

// VerifyTCPChecksum returns true if the TCP header checksum is correct
// for this packet, false otherwise. Note that the checksum is not
// modified.
func (p *Packet) VerifyTCPChecksum() bool {

	sum := p.computeTCPChecksum()

	return sum == p.TCPChecksum
}

// UpdateTCPChecksum computes the TCP header checksum and updates the
// packet with the value.
func (p *Packet) UpdateTCPChecksum() {

	p.TCPChecksum = p.computeTCPChecksum()

	binary.BigEndian.PutUint16(p.Buffer[TCPChecksumPos:TCPChecksumPos+2], p.TCPChecksum)
}

// String returns a string representation of fields contained in this packet.
func (p *Packet) String() string {

	var buf bytes.Buffer
	buf.WriteString("(error)")

	header, err := ipv4.ParseHeader(p.Buffer)

	if err == nil {
		buf.Reset()
		buf.WriteString(header.String())
		buf.WriteString(" srcport=")
		buf.WriteString(strconv.Itoa(int(p.SourcePort)))
		buf.WriteString(" dstport=")
		buf.WriteString(strconv.Itoa(int(p.DestinationPort)))
		buf.WriteString(" tcpcksum=")
		buf.WriteString(fmt.Sprintf("0x%0x", p.TCPChecksum))
		buf.WriteString(" data")
		buf.WriteString(hex.EncodeToString(p.GetBytes()))
	}
	return buf.String()
}

// Computes the IP header checksum. The packet is not modified.
func (p *Packet) computeIPChecksum() uint16 {

	// IP packet checksum is computed with the checksum value set to zero
	binary.BigEndian.PutUint16(p.Buffer[ipChecksumPos:ipChecksumPos+2], uint16(0))

	// Compute checksum, over IP header only
	sum := checksum(p.Buffer[0 : p.ipHeaderLen*4])

	// Restore the previous checksum (whether correct or not, as this function doesn't change it)
	binary.BigEndian.PutUint16(p.Buffer[ipChecksumPos:ipChecksumPos+2], p.ipChecksum)

	return sum
}

// Computes the TCP header checksum. The packet is not modified.
func (p *Packet) computeTCPChecksum() uint16 {

	var pseudoHeaderLen uint16 = 12
	tcpSize := uint16(len(p.Buffer)) - p.l4BeginPos
	bufLen := pseudoHeaderLen + tcpSize
	buf := make([]byte, bufLen)

	// Construct the pseudo-header for TCP checksum computation:

	// bytes 0-3: Source IP address
	copy(buf[0:4], p.Buffer[ipSourceAddrPos:ipSourceAddrPos+4])

	// bytes 4-7: Destination IP address
	copy(buf[4:8], p.Buffer[ipDestAddrPos:ipDestAddrPos+4])

	// byte 8: Constant zero
	buf[8] = 0

	// byte 9: Protocol (6==TCP)
	buf[9] = 6

	// bytes 10,11: TCP buffer size (real header + payload)
	binary.BigEndian.PutUint16(buf[10:12], tcpSize+uint16(len(p.tcpData)+len(p.tcpOptions)))

	// bytes 12+: The TCP buffer (real header + payload)
	copy(buf[12:], p.Buffer[p.l4BeginPos:])

	// Set current checksum to zero (in buf, not changing packet)
	buf[pseudoHeaderLen+16] = 0
	buf[pseudoHeaderLen+17] = 0

	buf = append(buf, p.tcpOptions...)
	buf = append(buf, p.tcpData...)

	return checksum(buf)
}

// incCsum16 implements rfc1624, equation 3.
func incCsum16(start, old, new uint16) uint16 {

	start = start ^ 0xffff
	old = old ^ 0xffff

	csum := uint32(start) + uint32(old) + uint32(new)
	for (csum >> 16) > 0 {
		csum = (csum & 0xffff) + ((csum >> 16) & 0xffff)
	}
	csum = csum ^ 0xffff
	return uint16(csum)
}

// Computes a sum of 16 bit numbers
func checksumDelta(buf []byte) uint16 {

	sum := uint32(0)

	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(sum)
}

// Computes a checksum over the given slice.
func checksum(buf []byte) uint16 {

	sum := checksumDelta(buf)
	csum := ^sum
	return csum
}
