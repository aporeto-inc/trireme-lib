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

	return sum == p.ipHdr.ipChecksum
}

// UpdateIPChecksum computes the IP header checksum and updates the
// packet with the value.
func (p *Packet) UpdateIPChecksum() {

	p.ipHdr.ipChecksum = p.computeIPChecksum()

	binary.BigEndian.PutUint16(p.ipHdr.Buffer[ipv4ChecksumPos:ipv4ChecksumPos+2], p.ipHdr.ipChecksum)
}

// VerifyTCPChecksum returns true if the TCP header checksum is correct
// for this packet, false otherwise. Note that the checksum is not
// modified.
func (p *Packet) VerifyTCPChecksum() bool {

	sum := p.computeTCPChecksum()

	return sum == p.tcpHdr.tcpChecksum
}

// UpdateTCPChecksum computes the TCP header checksum and updates the
// packet with the value.
func (p *Packet) UpdateTCPChecksum() {
	buffer := p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:]
	p.tcpHdr.tcpChecksum = p.computeTCPChecksum()
	binary.BigEndian.PutUint16(buffer[tcpChecksumPos:tcpChecksumPos+2], p.tcpHdr.tcpChecksum)
}

// UpdateTCPFlags
func (p *Packet) updateTCPFlags(tcpFlags uint8) {
	buffer := p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:]
	buffer[tcpFlagsOffsetPos] = tcpFlags
}

// ConvertAcktoFinAck function removes the data from the packet
// It is called only if the packet is Ack or Psh/Ack
// converts psh/ack to fin/ack packet.
func (p *Packet) ConvertAcktoFinAck() error {
	var tcpFlags uint8

	tcpFlags = tcpFlags | TCPFinMask
	tcpFlags = tcpFlags | TCPAckMask

	p.updateTCPFlags(tcpFlags)
	p.tcpHdr.tcpFlags = tcpFlags

	if err := p.TCPDataDetach(0); err != nil {
		return fmt.Errorf("ack packet in wrong format")
	}
	p.DropTCPDetachedBytes()
	return nil
}

//PacketToStringTCP returns a string representation of fields contained in this packet.
func (p *Packet) PacketToStringTCP() string {

	var buf bytes.Buffer
	buf.WriteString("(error)")

	header, err := ipv4.ParseHeader(p.ipHdr.Buffer)

	if err == nil {
		buf.Reset()
		buf.WriteString(header.String())
		buf.WriteString(" srcport=")
		buf.WriteString(strconv.Itoa(int(p.SourcePort())))
		buf.WriteString(" dstport=")
		buf.WriteString(strconv.Itoa(int(p.DestPort())))
		buf.WriteString(" tcpcksum=")
		buf.WriteString(fmt.Sprintf("0x%0x", p.tcpHdr.tcpChecksum))
		buf.WriteString(" data")
		buf.WriteString(hex.EncodeToString(p.GetTCPBytes()))
	}
	return buf.String()
}

// Computes the IP header checksum. The packet is not modified.
func (p *Packet) computeIPChecksum() uint16 {

	// IP packet checksum is computed with the checksum value set to zero
	p.ipHdr.Buffer[ipv4ChecksumPos] = 0
	p.ipHdr.Buffer[ipv4ChecksumPos+1] = 0

	// Compute checksum, over IP header only
	sum := checksum(p.ipHdr.Buffer[:p.ipHdr.ipHeaderLen])

	// Restore the previous checksum (whether correct or not, as this function doesn't change it)
	binary.BigEndian.PutUint16(p.ipHdr.Buffer[ipv4ChecksumPos:ipv4ChecksumPos+2], p.ipHdr.ipChecksum)

	return sum
}

// Computes the TCP header checksum. The packet is not modified.
func (p *Packet) computeTCPChecksum() uint16 {
	var buf [2]byte
	buffer := p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:]
	tcpBufSize := uint16(len(buffer) + len(p.tcpHdr.tcpData) + len(p.tcpHdr.tcpOptions))

	oldCsumLow := buffer[tcpChecksumPos]
	oldCsumHigh := buffer[tcpChecksumPos+1]

	// Put 0 to calculate the checksum. We will reset it back after the checksum
	buffer[tcpChecksumPos] = 0
	buffer[tcpChecksumPos+1] = 0

	csum := partialChecksum(0, p.ipHdr.Buffer[ipv4SourceAddrPos:ipv4SourceAddrPos+4])
	csum = partialChecksum(csum, p.ipHdr.Buffer[ipv4DestAddrPos:ipv4DestAddrPos+4])

	// reserved 0 byte
	buf[0] = 0
	// tcp option 6
	buf[1] = 6

	csum = partialChecksum(csum, buf[:])
	binary.BigEndian.PutUint16(buf[:], tcpBufSize)
	csum = partialChecksum(csum, buf[:])

	csum = partialChecksum(csum, buffer)
	csum = partialChecksum(csum, p.tcpHdr.tcpOptions)
	csum = partialChecksum(csum, p.tcpHdr.tcpData)

	csum16 := finalizeChecksum(csum)

	// restore the checksum
	buffer[tcpChecksumPos] = oldCsumLow
	buffer[tcpChecksumPos+1] = oldCsumHigh

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

	sum := init

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
	buffer := p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:]
	ignoreCheckSum := []byte{0, 0}
	p.udpHdr.udpChecksum = binary.BigEndian.Uint16(ignoreCheckSum[:])

	curLen := uint16(len(buffer))
	udpDataLen := curLen - p.GetUDPDataStartBytes()

	// update checksum.
	binary.BigEndian.PutUint16(buffer[udpChecksumPos:udpChecksumPos+2], p.udpHdr.udpChecksum)
	// update length.
	binary.BigEndian.PutUint16(buffer[udpLengthPos:udpLengthPos+2], udpDataLen+8)
}

// ReadUDPToken returnthe UDP token. Gets called only during the handshake process.
func (p *Packet) ReadUDPToken() []byte {
	buffer := p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:]
	// 8 byte udp header, 20 byte udp marker
	if len(buffer) <= udpJwtTokenOffset {
		return []byte{}
	}
	return buffer[udpJwtTokenOffset:]
}

// UDPTokenAttach attached udp packet signature and tokens.
func (p *Packet) UDPTokenAttach(udpdata []byte, udptoken []byte) {

	udpData := []byte{}
	udpData = append(udpData, udpdata...)
	udpData = append(udpData, udptoken...)

	packetLenIncrease := uint16(len(udpdata) + len(udptoken))

	// IP Header Processing
	p.FixupIPHdrOnDataModify(p.ipHdr.ipTotalLength, p.ipHdr.ipTotalLength+packetLenIncrease)

	// Attach Data @ the end of current buffer
	p.ipHdr.Buffer = append(p.ipHdr.Buffer, udpData...)

	p.UpdateUDPChecksum()
}

// UDPDataAttach Attaches UDP data post encryption.
func (p *Packet) UDPDataAttach(header, udpdata []byte) {

	// Attach Data @ the end of current buffer
	p.ipHdr.Buffer = append(p.ipHdr.Buffer, header...)
	p.ipHdr.Buffer = append(p.ipHdr.Buffer, udpdata...)
	// IP Header Processing
	p.FixupIPHdrOnDataModify(p.ipHdr.ipTotalLength, uint16(len(p.ipHdr.Buffer)))
	p.UpdateUDPChecksum()
}

// UDPDataDetach detaches UDP payload from the Buffer. Called only during Encrypt/Decrypt.
func (p *Packet) UDPDataDetach() {
	// Create constants for IP header + UDP header. copy ?
	p.ipHdr.Buffer = p.ipHdr.Buffer[:p.ipHdr.ipHeaderLen+UDPDataPos]
}

// CreateReverseFlowPacket modifies the packet for reverse flow.
func (p *Packet) CreateReverseFlowPacket(destIP net.IP, destPort uint16) {
	buffer := p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:]

	srcAddr := binary.BigEndian.Uint32(destIP.To4())
	destAddr := binary.BigEndian.Uint32(p.ipHdr.Buffer[ipv4DestAddrPos : ipv4DestAddrPos+4])

	// copy the fields
	binary.BigEndian.PutUint32(p.ipHdr.Buffer[ipv4SourceAddrPos:ipv4SourceAddrPos+4], destAddr)
	binary.BigEndian.PutUint32(p.ipHdr.Buffer[ipv4DestAddrPos:ipv4DestAddrPos+4], srcAddr)
	binary.BigEndian.PutUint16(buffer[udpSourcePortPos:udpSourcePortPos+2], p.udpHdr.destinationPort)
	binary.BigEndian.PutUint16(buffer[udpDestPortPos:udpDestPortPos+2], destPort)

	p.FixupIPHdrOnDataModify(p.ipHdr.ipTotalLength, uint16(p.ipHdr.ipHeaderLen+UDPDataPos))

	// Just get the IP/UDP header. Ignore the rest. No need for packet
	p.ipHdr.Buffer = p.ipHdr.Buffer[:p.ipHdr.ipHeaderLen+UDPDataPos]

	// change the fields
	p.ipHdr.sourceAddress = net.IP(p.ipHdr.Buffer[ipv4SourceAddrPos : ipv4SourceAddrPos+4])
	p.ipHdr.destinationAddress = destIP

	p.udpHdr.sourcePort = p.udpHdr.destinationPort
	p.udpHdr.destinationPort = destPort

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
	return GetUDPTypeFromBuffer(p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:])
}

// GetUDPTypeFromBuffer gets the UDP packet from a raw buffer.,
func GetUDPTypeFromBuffer(buffer []byte) byte {
	if len(buffer) < (UDPDataPos + UDPSignatureLen) {
		return 0
	}

	marker := buffer[UDPDataPos:udpSignatureEnd]

	// check for packet signature.
	if !bytes.Equal(buffer[udpAuthMarkerOffset:udpSignatureEnd], []byte(UDPAuthMarker)) {
		zap.L().Debug("Not an Aporeto control Packet")
		return 0
	}
	// control packet. byte 0 has packet type information.
	return marker[0] & UDPPacketMask
}

//GetTCPFlags returns the tcp flags from the packet
func (p *Packet) GetTCPFlags() uint8 {
	return p.tcpHdr.tcpFlags
}

//SetTCPFlags allows to set the tcp flags on the packet
func (p *Packet) SetTCPFlags(flags uint8) {
	p.tcpHdr.tcpFlags = flags
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
