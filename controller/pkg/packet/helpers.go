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

	return sum == p.IPHdr.ipChecksum
}

// UpdateIPChecksum computes the IP header checksum and updates the
// packet with the value.
func (p *Packet) UpdateIPChecksum() {

	p.IPHdr.ipChecksum = p.computeIPChecksum()

	binary.BigEndian.PutUint16(p.IPHdr.Buffer[ipv4ChecksumPos:ipv4ChecksumPos+2], p.IPHdr.ipChecksum)
}

// VerifyTCPChecksum returns true if the TCP header checksum is correct
// for this packet, false otherwise. Note that the checksum is not
// modified.
func (p *Packet) VerifyTCPChecksum() bool {

	sum := p.computeTCPChecksum()

	return sum == p.TCPHdr.tcpChecksum
}

// UpdateTCPChecksum computes the TCP header checksum and updates the
// packet with the value.
func (p *Packet) UpdateTCPChecksum() {
	buffer := p.IPHdr.Buffer[p.IPHdr.ipHeaderLen:]
	p.TCPHdr.tcpChecksum = p.computeTCPChecksum()
	binary.BigEndian.PutUint16(buffer[TCPChecksumPos:TCPChecksumPos+2], p.TCPHdr.tcpChecksum)
}

// UpdateTCPFlags
func (p *Packet) updateTCPFlags(tcpFlags uint8) {
	buffer := p.IPHdr.Buffer[p.IPHdr.ipHeaderLen:]
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
	p.TCPHdr.tcpFlags = tcpFlags

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

	header, err := ipv4.ParseHeader(p.IPHdr.Buffer)

	if err == nil {
		buf.Reset()
		buf.WriteString(header.String())
		buf.WriteString(" srcport=")
		buf.WriteString(strconv.Itoa(int(p.SourcePort())))
		buf.WriteString(" dstport=")
		buf.WriteString(strconv.Itoa(int(p.DestPort())))
		buf.WriteString(" tcpcksum=")
		buf.WriteString(fmt.Sprintf("0x%0x", p.TCPHdr.tcpChecksum))
		buf.WriteString(" data")
		buf.WriteString(hex.EncodeToString(p.GetBytes()))
	}
	return buf.String()
}

// Computes the IP header checksum. The packet is not modified.
func (p *Packet) computeIPChecksum() uint16 {

	// IP packet checksum is computed with the checksum value set to zero
	p.IPHdr.Buffer[ipv4ChecksumPos] = 0
	p.IPHdr.Buffer[ipv4ChecksumPos+1] = 0

	// Compute checksum, over IP header only
	sum := checksum(p.IPHdr.Buffer[:p.IPHdr.ipHeaderLen])

	// Restore the previous checksum (whether correct or not, as this function doesn't change it)
	binary.BigEndian.PutUint16(p.IPHdr.Buffer[ipv4ChecksumPos:ipv4ChecksumPos+2], p.IPHdr.ipChecksum)

	return sum
}

// Computes the TCP header checksum. The packet is not modified.
func (p *Packet) computeTCPChecksum() uint16 {
	var buf [2]byte
	buffer := p.IPHdr.Buffer[p.IPHdr.ipHeaderLen:]
	tcpBufSize := uint16(len(buffer) + len(p.TCPHdr.tcpData) + len(p.TCPHdr.tcpOptions))

	oldCsumLow := buffer[TCPChecksumPos]
	oldCsumHigh := buffer[TCPChecksumPos+1]

	// Put 0 to calculate the checksum. We will reset it back after the checksum
	buffer[TCPChecksumPos] = 0
	buffer[TCPChecksumPos+1] = 0

	csum := partialChecksum(0, p.IPHdr.Buffer[ipv4SourceAddrPos:ipv4SourceAddrPos+4])
	csum = partialChecksum(csum, p.IPHdr.Buffer[ipv4DestAddrPos:ipv4DestAddrPos+4])

	// reserved 0 byte
	buf[0] = 0
	// tcp option 6
	buf[1] = 6

	csum = partialChecksum(csum, buf[:])
	binary.BigEndian.PutUint16(buf[:], tcpBufSize)
	csum = partialChecksum(csum, buf[:])

	csum = partialChecksum(csum, buffer)
	csum = partialChecksum(csum, p.TCPHdr.tcpOptions)
	csum = partialChecksum(csum, p.TCPHdr.tcpData)

	csum16 := finalizeChecksum(csum)

	// restore the checksum
	buffer[TCPChecksumPos] = oldCsumLow
	buffer[TCPChecksumPos+1] = oldCsumHigh

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
	buffer := p.IPHdr.Buffer[p.IPHdr.ipHeaderLen:]
	ignoreCheckSum := []byte{0, 0}
	p.UDPHdr.udpChecksum = binary.BigEndian.Uint16(ignoreCheckSum[:])

	curLen := uint16(len(buffer))
	udpDataLen := curLen - p.GetUDPDataStartBytes()

	// update checksum.
	binary.BigEndian.PutUint16(buffer[UDPChecksumPos:UDPChecksumPos+2], p.UDPHdr.udpChecksum)
	// update length.
	binary.BigEndian.PutUint16(buffer[UDPLengthPos:UDPLengthPos+2], udpDataLen+8)
}

// ReadUDPToken returnthe UDP token. Gets called only during the handshake process.
func (p *Packet) ReadUDPToken() []byte {
	buffer := p.IPHdr.Buffer[p.IPHdr.ipHeaderLen:]
	// 8 byte udp header, 20 byte udp marker
	if len(buffer) <= UDPJwtTokenOffset {
		return []byte{}
	}
	return buffer[UDPJwtTokenOffset:]
}

// UDPTokenAttach attached udp packet signature and tokens.
func (p *Packet) UDPTokenAttach(udpdata []byte, udptoken []byte) {

	udpData := []byte{}
	udpData = append(udpData, udpdata...)
	udpData = append(udpData, udptoken...)

	p.UDPHdr.udpData = udpData

	packetLenIncrease := uint16(len(udpdata) + len(udptoken))

	// IP Header Processing
	p.FixupIPHdrOnDataModify(p.IPHdr.ipTotalLength, p.IPHdr.ipTotalLength+packetLenIncrease)

	// Attach Data @ the end of current buffer
	p.IPHdr.Buffer = append(p.IPHdr.Buffer, p.UDPHdr.udpData...)

	p.UpdateUDPChecksum()
}

// UDPDataAttach Attaches UDP data post encryption.
func (p *Packet) UDPDataAttach(udpdata []byte) {
	udpData := []byte{}
	udpData = append(udpData, udpdata...)
	p.UDPHdr.udpData = udpData
	// Attach Data @ the end of current buffer. Add it to the IP header as that will be used when setverdict is called.
	p.IPHdr.Buffer = append(p.IPHdr.Buffer, p.UDPHdr.udpData...)
	// IP Header Processing
	p.FixupIPHdrOnDataModify(p.IPHdr.ipTotalLength, uint16(len(p.IPHdr.Buffer)))
	p.UpdateUDPChecksum()
}

// UDPDataDetach detaches UDP payload from the Buffer. Called only during Encrypt/Decrypt.
func (p *Packet) UDPDataDetach() {
	// Create constants for IP header + UDP header. copy ?
	p.IPHdr.Buffer = p.IPHdr.Buffer[:p.IPHdr.ipHeaderLen+UDPDataPos]
	p.UDPHdr.udpData = []byte{}
	// IP header/checksum updated on DataAttach.
}

// CreateReverseFlowPacket modifies the packet for reverse flow.
func (p *Packet) CreateReverseFlowPacket(destIP net.IP, destPort uint16) {
	buffer := p.IPHdr.Buffer[p.IPHdr.ipHeaderLen:]

	srcAddr := binary.BigEndian.Uint32(destIP.To4())
	destAddr := binary.BigEndian.Uint32(p.IPHdr.Buffer[ipv4DestAddrPos : ipv4DestAddrPos+4])

	// copy the fields
	binary.BigEndian.PutUint32(p.IPHdr.Buffer[ipv4SourceAddrPos:ipv4SourceAddrPos+4], destAddr)
	binary.BigEndian.PutUint32(p.IPHdr.Buffer[ipv4DestAddrPos:ipv4DestAddrPos+4], srcAddr)
	binary.BigEndian.PutUint16(buffer[udpSourcePortPos:udpSourcePortPos+2], p.UDPHdr.destinationPort)
	binary.BigEndian.PutUint16(buffer[udpDestPortPos:udpDestPortPos+2], destPort)

	p.FixupIPHdrOnDataModify(p.IPHdr.ipTotalLength, uint16(p.IPHdr.ipHeaderLen+UDPDataPos))

	// Just get the IP/UDP header. Ignore the rest. No need for packet
	p.IPHdr.Buffer = p.IPHdr.Buffer[:p.IPHdr.ipHeaderLen+UDPDataPos]

	// change the fields
	p.IPHdr.sourceAddress = net.IP(p.IPHdr.Buffer[ipv4SourceAddrPos : ipv4SourceAddrPos+4])
	p.IPHdr.destinationAddress = destIP

	p.UDPHdr.sourcePort = p.UDPHdr.destinationPort
	p.UDPHdr.destinationPort = destPort

	p.UpdateIPChecksum()
	p.UpdateUDPChecksum()
}

// GetUDPType returns udp type of packet.
func (p *Packet) GetUDPType() byte {
	buffer := p.IPHdr.Buffer[p.IPHdr.ipHeaderLen:]
	// Every UDP control packet has a 20 byte packet signature. The
	// first 2 bytes represent the following control information.
	// Byte 0 : Bits 0,1 are reserved fields.
	//          Bits 2,3,4 represent version information.
	//          Bits 5,6 represent udp packet type,
	//          Bit 7 represents encryption. (currently unused).
	// Byte 1: reserved for future use.
	// Bytes [2:20]: Packet signature.
	if len(buffer) < (UDPDataPos + UDPSignatureLen) {
		// Not an Aporeto control packet.
		return 0
	}

	marker := buffer[UDPDataPos:UDPSignatureEnd]
	// check for packet signature.
	if !bytes.Equal(buffer[UDPAuthMarkerOffset:UDPSignatureEnd], []byte(UDPAuthMarker)) {
		zap.L().Debug("Not an Aporeto control Packet", zap.String("flow", p.L4FlowHash()))
		return 0
	}
	// control packet. byte 0 has packet type information.
	return marker[0] & UDPPacketMask
}

//GetTCPFlags returns the tcp flags from the packet
func (p *Packet) GetTCPFlags() uint8 {
	return p.TCPHdr.tcpFlags
}

//SetTCPFlags allows to set the tcp flags on the packet
func (p *Packet) SetTCPFlags(flags uint8) {
	p.TCPHdr.tcpFlags = flags
}
