package packet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"

	"go.uber.org/zap"
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

// UpdateTCPFlags
func (p *Packet) updateTCPFlags(tcpFlags uint8) {
	p.Buffer[tcpFlagsOffsetPos] = tcpFlags
}

// ConvertAcktoFinAck function removes the data from the packet
// It is called only if the packet is Ack or Psh/Ack
// converts psh/ack to fin/ack packet.
func (p *Packet) ConvertAcktoFinAck() error {
	var tcpFlags uint8

	tcpFlags = tcpFlags | TCPFinMask
	tcpFlags = tcpFlags | TCPAckMask

	p.updateTCPFlags(tcpFlags)
	p.TCPFlags = tcpFlags
	if err := p.TCPDataDetach(0); err != nil {
		return fmt.Errorf("ack packet in wrong format")
	}
	p.DropDetachedBytes()
	return nil
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

// UpdateUDPChecksum updates the UDP checksum field of packet
func (p *Packet) UpdateUDPChecksum() {

	// checksum set to 0, ignored by the stack
	ignoreCheckSum := []byte{0, 0}
	p.UDPChecksum = binary.BigEndian.Uint16(ignoreCheckSum[:])

	curLen := uint16(len(p.Buffer))
	udpDataLen := curLen - p.GetUDPDataStartBytes()

	// update checksum.
	binary.BigEndian.PutUint16(p.Buffer[UDPChecksumPos:UDPChecksumPos+2], p.UDPChecksum)
	// update length.
	binary.BigEndian.PutUint16(p.Buffer[UDPLengthPos:UDPLengthPos+2], udpDataLen+8)
}

// ReadUDPToken returnthe UDP token. Gets called only during the handshake process.
func (p *Packet) ReadUDPToken() []byte {

	// 20 byte IP hdr, 8 byte udp header, 20 byte udp marker
	if len(p.Buffer) <= UDPJwtTokenOffset {
		return []byte{}
	}
	return p.Buffer[UDPJwtTokenOffset:]
}

// UDPTokenAttach attached udp packet signature and tokens.
func (p *Packet) UDPTokenAttach(udpdata []byte, udptoken []byte) {

	udpData := []byte{}
	udpData = append(udpData, udpdata...)
	udpData = append(udpData, udptoken...)

	p.udpData = udpData

	packetLenIncrease := uint16(len(udpdata) + len(udptoken))

	// IP Header Processing
	p.FixupIPHdrOnDataModify(p.IPTotalLength, p.IPTotalLength+packetLenIncrease)

	// Attach Data @ the end of current buffer
	p.Buffer = append(p.Buffer, p.udpData...)

	p.UpdateUDPChecksum()
}

// UDPDataAttach Attaches UDP data post encryption.
func (p *Packet) UDPDataAttach(udpdata []byte) {

	udpData := []byte{}
	udpData = append(udpData, udpdata...)
	p.udpData = udpData
	packetLenIncrease := uint16(len(udpdata))

	// Attach Data @ the end of current buffer
	p.Buffer = append(p.Buffer, p.udpData...)
	// IP Header Processing
	p.FixupIPHdrOnDataModify(p.IPTotalLength, p.GetUDPDataStartBytes()+packetLenIncrease)
	p.UpdateUDPChecksum()
}

// UDPDataDetach detaches UDP payload from the Buffer. Called only during Encrypt/Decrypt.
func (p *Packet) UDPDataDetach() {

	// Create constants for IP header + UDP header. copy ?
	p.Buffer = p.Buffer[:UDPDataPos]
	p.udpData = []byte{}

	// IP header/checksum updated on DataAttach.
}

// CreateReverseFlowPacket modifies the packet for reverse flow.
func (p *Packet) CreateReverseFlowPacket(destIP net.IP, destPort uint16) {

	srcAddr := binary.BigEndian.Uint32(destIP.To4())
	destAddr := binary.BigEndian.Uint32(p.Buffer[ipDestAddrPos : ipDestAddrPos+4])

	// copy the fields
	binary.BigEndian.PutUint32(p.Buffer[ipSourceAddrPos:ipSourceAddrPos+4], destAddr)
	binary.BigEndian.PutUint32(p.Buffer[ipDestAddrPos:ipDestAddrPos+4], srcAddr)
	binary.BigEndian.PutUint16(p.Buffer[tcpSourcePortPos:tcpSourcePortPos+2], p.DestinationPort)
	binary.BigEndian.PutUint16(p.Buffer[tcpDestPortPos:tcpDestPortPos+2], destPort)

	p.FixupIPHdrOnDataModify(p.IPTotalLength, UDPDataPos)

	// Just get the IP/UDP header. Ignore the rest. No need for packet
	// validation here.
	p.Buffer = p.Buffer[:UDPDataPos]

	// change the fields
	p.SourceAddress = net.IP(p.Buffer[ipSourceAddrPos : ipSourceAddrPos+4])
	p.DestinationAddress = net.IP(p.Buffer[ipDestAddrPos : ipDestAddrPos+4])

	p.SourcePort = binary.BigEndian.Uint16(p.Buffer[tcpSourcePortPos : tcpSourcePortPos+2])
	p.DestinationPort = binary.BigEndian.Uint16(p.Buffer[tcpDestPortPos : tcpDestPortPos+2])

	p.UpdateIPChecksum()

	p.UpdateUDPChecksum()
}

// GetUDPType returns udp type of packet.
func (p *Packet) GetUDPType() byte {

	// Every UDP control packet has a 20 byte packet signature. The
	// first 2 bytes represent the following control information.
	// Byte 0 : Bits 0,1 are reserved fields.
	//          Bits 2,3,4 represent version information.
	//          Bits 5,6 represent udp packet type,
	//          Bit 7 represents encryption. (currently unused).
	// Byte 1: reserved for future use.
	// Bytes [2:20]: Packet signature.

	return GetUDPTypeFromBuffer(p.Buffer)

}

// GetUDPTypeFromBuffer gets the UDP packet from a raw buffer.,
func GetUDPTypeFromBuffer(buffer []byte) byte {

	if len(buffer) < (UDPDataPos + UDPSignatureLen) {
		return 0
	}

	marker := buffer[UDPDataPos:UDPSignatureEnd]

	// check for packet signature.
	if !bytes.Equal(buffer[UDPAuthMarkerOffset:UDPSignatureEnd], []byte(UDPAuthMarker)) {
		zap.L().Debug("Not an Aporeto control Packet")
		return 0
	}
	// control packet. byte 0 has packet type information.
	return marker[0] & UDPPacketMask
}

// CreateUDPAuthMarker creates a UDP auth marker.
func CreateUDPAuthMarker(packetType uint8) []byte {

	// Every UDP control packet has a 20 byte packet signature. The
	// first 2 bytes represent the following control information.
	// Byte 0 : Bits 0,1 are reserved fields.
	//          Bits 2,3,4 represent version information.
	//          Bits 5, 6, 7 represent udp packet type,
	// Byte 1: reserved for future use.
	// Bytes [2:20]: Packet signature.

	marker := make([]byte, UDPSignatureLen)
	// ignore version info as of now.
	marker[0] |= packetType // byte 0
	marker[1] = 0           // byte 1
	// byte 2 - 19
	copy(marker[2:], []byte(UDPAuthMarker))

	return marker
}
