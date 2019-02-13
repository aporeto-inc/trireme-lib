package packet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"

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

	return sum == p.IpHdr.ipChecksum
}

// UpdateIPChecksum computes the IP header checksum and updates the
// packet with the value.
func (p *Packet) UpdateIPChecksum() {

	p.IpHdr.ipChecksum = p.computeIPChecksum()

	binary.BigEndian.PutUint16(p.IpHdr.Buffer[ipv4ChecksumPos:ipv4ChecksumPos+2], p.IpHdr.ipChecksum)
}

// VerifyTCPChecksum returns true if the TCP header checksum is correct
// for this packet, false otherwise. Note that the checksum is not
// modified.
func (p *Packet) VerifyTCPChecksum() bool {

	sum := p.computeTCPChecksum()

	return sum == p.tcpHdr.TCPChecksum
}

// UpdateTCPChecksum computes the TCP header checksum and updates the
// packet with the value.
func (p *Packet) UpdateTCPChecksum() {

	p.tcpHdr.TCPChecksum = p.computeTCPChecksum()

	binary.BigEndian.PutUint16(p.tcpHdr.Buffer[TCPChecksumPos:TCPChecksumPos+2], p.tcpHdr.TCPChecksum)
}

// UpdateTCPFlags
func (p *Packet) updateTCPFlags(tcpFlags uint8) {
	p.tcpHdr.Buffer[tcpFlagsOffsetPos] = tcpFlags
}

// ConvertAcktoFinAck function removes the data from the packet
// It is called only if the packet is Ack or Psh/Ack
// converts psh/ack to fin/ack packet.
func (p *Packet) ConvertAcktoFinAck() error {
	var tcpFlags uint8

	tcpFlags = tcpFlags | TCPFinMask
	tcpFlags = tcpFlags | TCPAckMask

	p.updateTCPFlags(tcpFlags)
	p.tcpHdr.TCPFlags = tcpFlags

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

	header, err := ipv4.ParseHeader(p.IpHdr.Buffer)

	if err == nil {
		buf.Reset()
		buf.WriteString(header.String())
		buf.WriteString(" srcport=")
		buf.WriteString(p.SourcePort())
		buf.WriteString(" dstport=")
		buf.WriteString(p.DestPort())
		buf.WriteString(" tcpcksum=")
		buf.WriteString(fmt.Sprintf("0x%0x", p.tcpHdr.TCPChecksum))
		buf.WriteString(" data")
		buf.WriteString(hex.EncodeToString(p.GetBytes()))
	}
	return buf.String()
}

// Computes the IP header checksum. The packet is not modified.
func (p *Packet) computeIPChecksum() uint16 {

	// IP packet checksum is computed with the checksum value set to zero
	binary.BigEndian.PutUint16(p.IpHdr.Buffer[ipv4ChecksumPos:ipv4ChecksumPos+2], uint16(0))

	// Compute checksum, over IP header only
	sum := checksum(p.IpHdr.Buffer[0 : p.IpHdr.ipHeaderLen*4])

	// Restore the previous checksum (whether correct or not, as this function doesn't change it)
	binary.BigEndian.PutUint16(p.IpHdr.Buffer[ipv4ChecksumPos:ipv4ChecksumPos+2], p.IpHdr.ipChecksum)

	return sum
}

// Computes the TCP header checksum. The packet is not modified.
func (p *Packet) computeTCPChecksum() uint16 {
	var buf [2]byte
	tcpBufSize := uint16(len(p.tcpHdr.Buffer) + len(p.tcpHdr.tcpData) + len(p.tcpHdr.tcpOptions))

	oldCsumLow := p.tcpHdr.Buffer[TCPChecksumPos]
	oldCsumHigh := p.tcpHdr.Buffer[TCPChecksumPos+1]

	// Put 0 to calculate the checksum. We will reset it back after the checksum
	p.tcpHdr.Buffer[TCPChecksumPos] = 0
	p.tcpHdr.Buffer[TCPChecksumPos+1] = 0

	csum := partialChecksum(0, p.IpHdr.Buffer[ipv4SourceAddrPos:ipv4SourceAddrPos+4])
	csum = partialChecksum(csum, p.IpHdr.Buffer[ipv4DestAddrPos:ipv4DestAddrPos+4])

	// reserverd 0 byte
	buf[0] = 0
	// tcp option 6
	buf[1] = 6

	csum = partialChecksum(csum, buf[:])
	binary.BigEndian.PutUint16(buf[:], tcpBufSize)
	csum = partialChecksum(csum, buf[:])

	csum = partialChecksum(csum, p.tcpHdr.Buffer)
	csum = partialChecksum(csum, p.tcpHdr.tcpOptions)
	csum = partialChecksum(csum, p.tcpHdr.tcpData)

	csum16 := finalizeChecksum(csum)

	// restore the checksum
	p.tcpHdr.Buffer[TCPChecksumPos] = oldCsumLow
	p.tcpHdr.Buffer[TCPChecksumPos+1] = oldCsumHigh

	return csum16
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

func csumConvert32To16bit(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return uint16(sum)
}

// Computes a sum of 16 bit numbers
func checksumDelta(init uint32, buf []byte) uint32 {

	sum := uint32(init)

	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}

	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}

	return sum
}

// Computes a checksum over the given slice.
func checksum(buf []byte) uint16 {
	sum32 := checksumDelta(0, buf)
	sum16 := csumConvert32To16bit(sum32)

	csum := ^sum16
	return csum
}

func partialChecksum(csum uint32, buf []byte) uint32 {
	return checksumDelta(csum, buf)
}

func finalizeChecksum(csum32 uint32) uint16 {
	csum16 := csumConvert32To16bit(csum32)
	csum := ^csum16

	return csum
}

// UpdateUDPChecksum updates the UDP checksum field of packet
func (p *Packet) UpdateUDPChecksum() {

	// checksum set to 0, ignored by the stack
	ignoreCheckSum := []byte{0, 0}
	p.udpHdr.UDPChecksum = binary.BigEndian.Uint16(ignoreCheckSum[:])

	curLen := uint16(len(p.udpHdr.Buffer))
	udpDataLen := curLen - p.GetUDPDataStartBytes()

	// update checksum.
	binary.BigEndian.PutUint16(p.udpHdr.Buffer[UDPChecksumPos:UDPChecksumPos+2], p.udpHdr.UDPChecksum)
	// update length.
	binary.BigEndian.PutUint16(p.udpHdr.Buffer[UDPLengthPos:UDPLengthPos+2], udpDataLen+8)
}

// ReadUDPToken returnthe UDP token. Gets called only during the handshake process.
func (p *Packet) ReadUDPToken() []byte {

	// 20 byte IP hdr, 8 byte udp header, 20 byte udp marker
	if len(p.udpHdr.Buffer) <= UDPJwtTokenOffset {
		return []byte{}
	}
	return p.udpHdr.Buffer[UDPJwtTokenOffset:]
}

// UDPTokenAttach attached udp packet signature and tokens.
func (p *Packet) UDPTokenAttach(udpdata []byte, udptoken []byte) {

	udpData := []byte{}
	udpData = append(udpData, udpdata...)
	udpData = append(udpData, udptoken...)

	p.udpHdr.udpData = udpData

	packetLenIncrease := uint16(len(udpdata) + len(udptoken))

	// IP Header Processing
	p.FixupIPHdrOnDataModify(p.IpHdr.IPTotalLength, p.IpHdr.IPTotalLength+packetLenIncrease)

	// Attach Data @ the end of current buffer
	p.IpHdr.Buffer = append(p.IpHdr.Buffer, p.udpHdr.udpData...)

	p.UpdateUDPChecksum()
}

// UDPDataAttach Attaches UDP data post encryption.
func (p *Packet) UDPDataAttach(udpdata []byte) {

	udpData := []byte{}
	udpData = append(udpData, udpdata...)
	p.udpHdr.udpData = udpData
	packetLenIncrease := uint16(len(udpdata))

	// Attach Data @ the end of current buffer. Add it to the IP header as that will be used when setverdict is called.
	p.IpHdr.Buffer = append(p.IpHdr.Buffer, p.udpHdr.udpData...)
	// IP Header Processing
	p.FixupIPHdrOnDataModify(p.IpHdr.IPTotalLength, p.GetUDPDataStartBytes()+packetLenIncrease)
	p.UpdateUDPChecksum()
}

// UDPDataDetach detaches UDP payload from the Buffer. Called only during Encrypt/Decrypt.
func (p *Packet) UDPDataDetach() {

	// Create constants for IP header + UDP header. copy ?
	p.udpHdr.Buffer = p.udpHdr.Buffer[:UDPDataPos]
	p.udpHdr.udpData = []byte{}

	// IP header/checksum updated on DataAttach.
}

// CreateReverseFlowPacket modifies the packet for reverse flow.
func (p *Packet) CreateReverseFlowPacket(destIP net.IP, destPort uint16) {

	srcAddr := binary.BigEndian.Uint32(destIP.To4())
	destAddr := binary.BigEndian.Uint32(p.IpHdr.Buffer[ipv4DestAddrPos : ipv4DestAddrPos+4])

	// copy the fields
	binary.BigEndian.PutUint32(p.IpHdr.Buffer[ipv4SourceAddrPos:ipv4SourceAddrPos+4], destAddr)
	binary.BigEndian.PutUint32(p.IpHdr.Buffer[ipv4DestAddrPos:ipv4DestAddrPos+4], srcAddr)
	binary.BigEndian.PutUint16(p.udpHdr.Buffer[udpSourcePortPos:udpSourcePortPos+2], p.udpHdr.DestinationPort)
	binary.BigEndian.PutUint16(p.udpHdr.Buffer[udpDestPortPos:udpDestPortPos+2], destPort)

	p.FixupIPHdrOnDataModify(p.IpHdr.IPTotalLength, minIPv4HdrSize+UDPDataPos)

	// Just get the IP/UDP header. Ignore the rest. No need for packet
	// validation here.
	// Extend the ip buffer to include the tcp.
	p.IpHdr.Buffer = p.IpHdr.Buffer[:minIPv4HdrSize+UDPDataPos]

	// change the fields
	p.IpHdr.SourceAddress = p.IpHdr.DestinationAddress
	p.IpHdr.DestinationAddress = destIP

	p.udpHdr.SourcePort = p.udpHdr.DestinationPort
	p.udpHdr.DestinationPort = destPort

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
	if len(p.udpHdr.Buffer) < (UDPDataPos + UDPSignatureLen) {
		// Not an Aporeto control packet.
		return 0
	}

	marker := p.udpHdr.Buffer[UDPDataPos:UDPSignatureEnd]
	// check for packet signature.
	if !bytes.Equal(p.udpHdr.Buffer[UDPAuthMarkerOffset:UDPSignatureEnd], []byte(UDPAuthMarker)) {
		zap.L().Debug("Not an Aporeto control Packet", zap.String("flow", p.L4FlowHash()))
		return 0
	}
	// control packet. byte 0 has packet type information.
	return marker[0] & UDPPacketMask
}
