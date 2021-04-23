// Package packet support for TCP/IP packet manipulations
// needed by the Aporeto infrastructure.
package packet

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"

	"go.uber.org/zap"
)

// printCount prints the debug header for packets every few lines that it prints
var printCount int

var errIPPacketCorrupt = errors.New("IP packet is smaller than min IP size of 20")
var errTCPAuthOption = errors.New("tcp authentication option not found")

//NewPacket is a method called on Packet which decodes the packet into the struct
func (p *Packet) NewPacket(context uint64, bytes []byte, mark string, lengthValidate bool) (err error) {

	// Get the mark value
	p.Mark = mark

	// Set the context
	p.context = context
	if len(bytes) < ipv4HdrLenPos {
		return fmt.Errorf("invalid packet length %d", len(bytes))
	}
	if bytes[ipv4HdrLenPos]&ipv4ProtoMask == 0x40 {
		p.ipHdr.version = V4
		return p.parseIPv4Packet(bytes, lengthValidate)
	}

	p.ipHdr.version = V6
	return p.parseIPv6Packet(bytes, lengthValidate)
}

// New returns a pointer to Packet structure built from the
// provided bytes buffer which is expected to contain valid TCP/IP
// packet bytes.
// WARNING: This package takes control of the bytes buffer passed. The caller has
// to be aware calling any function that returns a slice will NOT be a copy rather
// a sub-slice of the bytes buffer passed. It is the responsibility of the caller
// to copy the slice If and when necessary.
func New(context uint64, bytes []byte, mark string, lengthValidate bool) (packet *Packet, err error) {

	var p Packet

	// Get the mark value
	p.Mark = mark

	// Set the context
	p.context = context
	if len(bytes) < ipv4HdrLenPos {
		return nil, fmt.Errorf("invalid packet length %d", len(bytes))
	}
	if bytes[ipv4HdrLenPos]&ipv4ProtoMask == 0x40 {
		p.ipHdr.version = V4
		return &p, p.parseIPv4Packet(bytes, lengthValidate)
	}

	p.ipHdr.version = V6
	return &p, p.parseIPv6Packet(bytes, lengthValidate)
}

func (p *Packet) parseTCP(bytes []byte) {
	// TCP Header Processing
	tcpBuffer := bytes[p.ipHdr.ipHeaderLen:]

	p.tcpHdr.tcpChecksum = binary.BigEndian.Uint16(tcpBuffer[tcpChecksumPos : tcpChecksumPos+2])
	p.tcpHdr.sourcePort = binary.BigEndian.Uint16(tcpBuffer[tcpSourcePortPos : tcpSourcePortPos+2])
	p.tcpHdr.destinationPort = binary.BigEndian.Uint16(tcpBuffer[tcpDestPortPos : tcpDestPortPos+2])
	p.tcpHdr.tcpAck = binary.BigEndian.Uint32(tcpBuffer[tcpAckPos : tcpAckPos+4])
	p.tcpHdr.tcpSeq = binary.BigEndian.Uint32(tcpBuffer[tcpSeqPos : tcpSeqPos+4])
	p.tcpHdr.tcpDataOffset = (tcpBuffer[tcpDataOffsetPos] & tcpDataOffsetMask) >> 4
	p.tcpHdr.tcpTotalLength = uint16(len(p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:]))

	p.SetTCPFlags(tcpBuffer[tcpFlagsOffsetPos])
}

func parseIP(s string, ipv4 bool) (net.IP, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address : %s", s)
	}
	if ipv4 {
		ip = ip.To4()
		if ip == nil {
			return nil, fmt.Errorf("not a valid IPv4 address : %s", s)
		}
	} else {
		ip = ip.To16()
		if ip == nil {
			return nil, fmt.Errorf("not a valid IPv6 address : %s", s)
		}
	}
	return ip, nil
}

// NewIpv4TCPPacket creates an Ipv4/TCP packet
func NewIpv4TCPPacket(context uint64, tcpFlags uint8, src, dst string, srcPort, desPort uint16) (*Packet, error) {

	var p Packet
	p.context = context
	p.ipHdr.version = V4

	srcIP, err := parseIP(src, true)
	if err != nil {
		return nil, fmt.Errorf("source address : %s", err)
	}
	dstIP, err := parseIP(dst, true)
	if err != nil {
		return nil, fmt.Errorf("destination address : %s", err)
	}

	buffer := make([]byte, minIPv4HdrSize+minTCPHeaderLen)
	buffer[ipv4HdrLenPos] = 0x45
	copy(buffer[ipv4SourceAddrPos:ipv4SourceAddrPos+4], srcIP)
	copy(buffer[ipv4DestAddrPos:ipv4DestAddrPos+4], dstIP)

	buffer[ipv4ProtoPos] = uint8(IPProtocolTCP)
	binary.BigEndian.PutUint16(buffer[ipv4LengthPos:ipv4LengthPos+2], uint16(minIPv4HdrSize+minTCPHeaderLen))

	// TCP data
	tcpBuffer := buffer[minIPv4HdrSize:]
	tcpBuffer[tcpFlagsOffsetPos] = tcpFlags
	binary.BigEndian.PutUint16(tcpBuffer[tcpSourcePortPos:tcpSourcePortPos+2], srcPort)
	binary.BigEndian.PutUint16(tcpBuffer[tcpDestPortPos:tcpDestPortPos+2], desPort)
	tcpBuffer[tcpDataOffsetPos] = 5 << 4

	if err := p.parseIPv4Packet(buffer, true); err != nil {
		return nil, err
	}

	p.UpdateIPv4Checksum()
	p.UpdateTCPChecksum()

	return &p, nil
}

// NewIpv6TCPPacket creates an Ipv6/TCP packet
func NewIpv6TCPPacket(context uint64, tcpFlags uint8, src, dst string, srcPort, desPort uint16) (*Packet, error) {

	var p Packet
	p.context = context
	p.ipHdr.version = V6

	srcIP, err := parseIP(src, false)
	if err != nil {
		return nil, fmt.Errorf("source address : %s", err)
	}
	dstIP, err := parseIP(dst, false)
	if err != nil {
		return nil, fmt.Errorf("destination address : %s", err)
	}

	buffer := make([]byte, ipv6HeaderLen+minTCPHeaderLen)

	buffer[ipv6VersionPos] = 6
	binary.BigEndian.PutUint16(buffer[ipv6PayloadLenPos:ipv6PayloadLenPos+2], minTCPHeaderLen)
	copy(buffer[ipv6SourceAddrPos:ipv6SourceAddrPos+16], srcIP.To16())
	copy(buffer[ipv6DestAddrPos:ipv6DestAddrPos+16], dstIP.To16())

	buffer[ipv6ProtoPos] = uint8(IPProtocolTCP)

	// TCP data
	tcpBuffer := buffer[ipv6HeaderLen:]
	tcpBuffer[tcpFlagsOffsetPos] = tcpFlags
	binary.BigEndian.PutUint16(tcpBuffer[tcpSourcePortPos:tcpSourcePortPos+2], srcPort)
	binary.BigEndian.PutUint16(tcpBuffer[tcpDestPortPos:tcpDestPortPos+2], desPort)
	tcpBuffer[tcpDataOffsetPos] = 5 << 4

	if err := p.parseIPv6Packet(buffer, true); err != nil {
		return nil, err
	}

	p.UpdateTCPChecksum()

	return &p, nil
}

func (p *Packet) parseICMP(bytes []byte) {

	icmpBuffer := bytes[p.ipHdr.ipHeaderLen:]
	p.icmpHdr.icmpType = int8(icmpBuffer[0])
	p.icmpHdr.icmpCode = int8(icmpBuffer[1])
}

func (p *Packet) parseUDP(bytes []byte) {
	// UDP Header Processing
	udpBuffer := bytes[p.ipHdr.ipHeaderLen:]

	p.udpHdr.udpChecksum = binary.BigEndian.Uint16(udpBuffer[udpChecksumPos : udpChecksumPos+2])
	p.udpHdr.udpLength = binary.BigEndian.Uint16(udpBuffer[udpLengthPos : udpLengthPos+2])
	p.udpHdr.udpData = []byte{}

	p.udpHdr.sourcePort = binary.BigEndian.Uint16(udpBuffer[udpSourcePortPos : udpSourcePortPos+2])
	p.udpHdr.destinationPort = binary.BigEndian.Uint16(udpBuffer[udpDestPortPos : udpDestPortPos+2])
}

func (p *Packet) parseIPv4Packet(bytes []byte, lengthValidate bool) (err error) {

	// IP Header Processing
	if len(bytes) < minIPv4HdrSize {
		return errIPPacketCorrupt
	}

	p.ipHdr.ipHeaderLen = (bytes[ipv4HdrLenPos] & ipv4HdrLenMask) * 4
	p.ipHdr.ipProto = bytes[ipv4ProtoPos]
	p.ipHdr.ipTotalLength = binary.BigEndian.Uint16(bytes[ipv4LengthPos : ipv4LengthPos+2])
	p.ipHdr.ipID = binary.BigEndian.Uint16(bytes[ipv4IDPos : ipv4IDPos+2])
	p.ipHdr.ipChecksum = binary.BigEndian.Uint16(bytes[ipv4ChecksumPos : ipv4ChecksumPos+2])
	p.ipHdr.sourceAddress = append([]byte{}, bytes[ipv4SourceAddrPos:ipv4SourceAddrPos+4]...)
	p.ipHdr.destinationAddress = append([]byte{}, bytes[ipv4DestAddrPos:ipv4DestAddrPos+4]...)

	if p.ipHdr.ipHeaderLen != minIPv4HdrSize {
		return fmt.Errorf("packets with ip options not supported: hdrlen=%d", p.ipHdr.ipHeaderLen)
	}

	p.ipHdr.Buffer = bytes

	if lengthValidate && p.ipHdr.ipTotalLength != uint16(len(p.ipHdr.Buffer)) {
		if p.ipHdr.ipTotalLength < uint16(len(p.ipHdr.Buffer)) {
			p.ipHdr.Buffer = p.ipHdr.Buffer[:p.ipHdr.ipTotalLength]
		} else {
			return fmt.Errorf("stated ip packet length %d differs from bytes available %d", p.ipHdr.ipTotalLength, len(p.ipHdr.Buffer))
		}
	}

	// Some sanity checking for TCP.
	if p.ipHdr.ipProto == IPProtocolTCP {
		if p.ipHdr.ipTotalLength-uint16(p.ipHdr.ipHeaderLen) < minTCPIPPacketLen {
			return fmt.Errorf("tcp ip packet too small: hdrlen=%d", p.ipHdr.ipHeaderLen)
		}

		p.parseTCP(bytes)
	}

	// Some sanity checking for UDP.
	if p.ipHdr.ipProto == IPProtocolUDP {
		if p.ipHdr.ipTotalLength-uint16(p.ipHdr.ipHeaderLen) < minUDPIPPacketLen {
			return fmt.Errorf("udp ip packet too small: hdrlen=%d", p.ipHdr.ipHeaderLen)
		}

		p.parseUDP(bytes)
	}

	if p.ipHdr.ipProto == IPProtocolICMP {
		if p.ipHdr.ipTotalLength-uint16(p.ipHdr.ipHeaderLen) < minICMPIPPacketLen {
			return fmt.Errorf("tcp ip packet too small: hdrlen=%d", p.ipHdr.ipHeaderLen)
		}

		p.parseICMP(bytes)
	}

	// Chaching the result of the flow hash for performance optimization.
	// It is called in multiple places.
	p.l4flowhash = p.l4FlowHash()

	return nil
}

func (p *Packet) parseIPv6Packet(bytes []byte, lengthValidate bool) (err error) {
	// IP Header Processing
	p.ipHdr.ipHeaderLen = ipv6HeaderLen
	p.ipHdr.ipProto = bytes[ipv6ProtoPos]
	p.ipHdr.ipTotalLength = ipv6HeaderLen + binary.BigEndian.Uint16(bytes[ipv6PayloadLenPos:ipv6PayloadLenPos+2])
	p.ipHdr.sourceAddress = append([]byte{}, bytes[ipv6SourceAddrPos:ipv6SourceAddrPos+16]...)
	p.ipHdr.destinationAddress = append([]byte{}, bytes[ipv6DestAddrPos:ipv6DestAddrPos+16]...)

	p.ipHdr.Buffer = bytes

	if lengthValidate && p.ipHdr.ipTotalLength != uint16(len(p.ipHdr.Buffer)) {
		if p.ipHdr.ipTotalLength < uint16(len(p.ipHdr.Buffer)) {
			p.ipHdr.Buffer = p.ipHdr.Buffer[:p.ipHdr.ipTotalLength]
		} else {
			return fmt.Errorf("stated ip packet length %d differs from bytes available %d", p.ipHdr.ipTotalLength, len(p.ipHdr.Buffer))
		}

		p.parseTCP(bytes)
	}

	// Some sanity checking for TCP.
	if p.ipHdr.ipProto == IPProtocolTCP {
		if p.ipHdr.ipTotalLength-uint16(p.ipHdr.ipHeaderLen) < minTCPIPPacketLen {
			return fmt.Errorf("tcp ip packet too small: hdrlen=%d", p.ipHdr.ipHeaderLen)
		}

		p.parseTCP(bytes)
	}

	// Some sanity checking for UDP.
	if p.ipHdr.ipProto == IPProtocolUDP {
		if p.ipHdr.ipTotalLength-uint16(p.ipHdr.ipHeaderLen) < minUDPIPPacketLen {
			return fmt.Errorf("udp ip packet too small: hdrlen=%d", p.ipHdr.ipHeaderLen)
		}
		p.parseUDP(bytes)
	}

	// Chaching the result of the flow hash for performance optimization.
	// It is called in multiple places.
	p.l4flowhash = p.l4FlowHash()

	return nil
}

// IsEmptyTCPPayload returns the TCP data offset
func (p *Packet) IsEmptyTCPPayload() bool {
	return p.TCPDataStartBytes() == p.tcpHdr.tcpTotalLength
}

// GetUDPData return additional data in packet
func (p *Packet) GetUDPData() []byte {
	return p.ipHdr.Buffer[p.ipHdr.ipHeaderLen+UDPDataPos:]
}

// GetUDPDataStartBytes return start of UDP data
func (p *Packet) GetUDPDataStartBytes() uint16 {
	return UDPDataPos
}

// TCPDataStartBytes provides the tcp data start offset in bytes
func (p *Packet) TCPDataStartBytes() uint16 {
	return uint16(p.tcpHdr.tcpDataOffset) * 4
}

// GetIPLength returns the IP length
func (p *Packet) GetIPLength() uint16 {
	return p.ipHdr.ipTotalLength
}

// Print is a print helper function
func (p *Packet) Print(context uint64, packetLogLevel bool) {

	if p.ipHdr.ipProto != IPProtocolTCP {
		return
	}

	logPkt := false
	detailed := false

	if packetLogLevel || context == 0 {
		logPkt = true
		detailed = true
	}

	var buf string
	print := false

	if logPkt {
		if printCount%200 == 0 {
			buf += fmt.Sprintf("Packet: %5s %5s %25s %15s %5s %15s %5s %6s %20s %20s %6s %20s %20s %2s %5s %5s\n",
				"IPID", "Dir", "Comment", "SIP", "SP", "DIP", "DP", "Flags", "TCPSeq", "TCPAck", "TCPLen", "ExpAck", "ExpSeq", "DO", "Acsum", "Ccsum")
		}
		printCount++
		offset := 0

		if (p.GetTCPFlags() & TCPSynMask) == TCPSynMask {
			offset = 1
		}

		expAck := p.tcpHdr.tcpSeq + uint32(uint16(len(p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:]))-p.TCPDataStartBytes()) + uint32(offset)
		ccsum := p.computeTCPChecksum()
		csumValidationStr := ""

		if p.tcpHdr.tcpChecksum != ccsum {
			csumValidationStr = "Bad Checksum"
		}

		buf += fmt.Sprintf("Packet: %5d %5s %25s %15s %5d %15s %5d %6s %20d %20d %6d %20d %20d %2d %5d %5d %12s\n",
			p.ipHdr.ipID,
			flagsToDir(p.context|context),
			flagsToStr(p.context|context),
			p.ipHdr.sourceAddress.String(), p.tcpHdr.sourcePort,
			p.ipHdr.destinationAddress.String(), p.tcpHdr.destinationPort,
			tcpFlagsToStr(p.GetTCPFlags()),
			p.tcpHdr.tcpSeq, p.tcpHdr.tcpAck, uint16(len(p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:]))-p.TCPDataStartBytes(),
			expAck, expAck, p.tcpHdr.tcpDataOffset,
			p.tcpHdr.tcpChecksum, ccsum, csumValidationStr)
		print = true
	}

	if detailed {
		pktBytes := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 8, 0}
		pktBytes = append(pktBytes, p.ipHdr.Buffer...)
		buf += fmt.Sprintf("%s\n", hex.Dump(pktBytes))
		print = true
	}

	if print {
		zap.L().Debug(buf)
	}
}

//UpdatePacketBuffer updates the packet with the new updates buffer.
func (p *Packet) UpdatePacketBuffer(buffer []byte, tcpOptionsLen uint16) error {

	if tcpOptionsLen != 0 {
		// If the packet has a payload then we can't insert options
		if p.TCPDataStartBytes() != uint16(len(p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:])) {
			return fmt.Errorf("cannot insert options with existing data: optionlength=%d, iptotallength=%d", tcpOptionsLen, p.ipHdr.ipTotalLength)
		}
	} else {
		// This case is for adding a payload to a packet which may or may not have options
		tcpOptionsLen := p.TCPDataStartBytes() - minTCPHeaderLen
		// Working with unsigned numbers so make sure we didn't go negative basically
		if p.TCPDataStartBytes() < tcpOptionsLen {
			return fmt.Errorf("cannot payload: bad options length: optionlength=%d", tcpOptionsLen)
		}
	}

	packetLenIncrease := uint16(len(buffer) - len(p.ipHdr.Buffer))
	p.ipHdr.Buffer = buffer

	// IP Header Processing
	p.FixupIPHdrOnDataModify(p.ipHdr.ipTotalLength, p.ipHdr.ipTotalLength+packetLenIncrease)

	// TCP Header Processing
	p.FixuptcpHdrOnTCPDataAttach(tcpOptionsLen)

	p.UpdateTCPChecksum()
	return nil
}

//GetTCPBytes returns the bytes in the packet. It consolidates in case of changes as well
func (p *Packet) GetTCPBytes() []byte {

	pktBytes := []byte{}
	pktBytes = append(pktBytes, p.ipHdr.Buffer...)
	return pktBytes
}

// ReadTCPDataString returns ths payload in a string variable
// It does not remove the payload from the packet
func (p *Packet) ReadTCPDataString() string {
	return string(p.ReadTCPData())
}

// ReadTCPData returns ths payload in a string variable
// It does not remove the payload from the packet
func (p *Packet) ReadTCPData() []byte {
	return p.ipHdr.Buffer[uint16(p.ipHdr.ipHeaderLen)+p.TCPDataStartBytes():]
}

// CheckTCPAuthenticationOption ensures authentication option exists at the offset provided
func (p *Packet) CheckTCPAuthenticationOption(iOptionLength int) (err error) {
	tcpDataStart := p.TCPDataStartBytes()

	if tcpDataStart <= minTCPIPPacketLen {
		return errTCPAuthOption
	}
	if len(p.ipHdr.Buffer) < int(p.ipHdr.ipHeaderLen)+20 {
		return errors.New("Invalid IP Packet")
	}
	if int(p.ipHdr.ipHeaderLen)+int(p.tcpHdr.tcpDataOffset*4) > len(p.ipHdr.Buffer) {
		return errors.New("Invalid TCP Packet")
	}
	buffer := p.ipHdr.Buffer[p.ipHdr.ipHeaderLen+20 : int(p.ipHdr.ipHeaderLen)+int(p.tcpHdr.tcpDataOffset*4)]

	for i := 0; i < len(buffer); {
		if buffer[i] == 0 || buffer[i] == 1 {
			i++
			continue
		}

		if buffer[i] != TCPAuthenticationOption {
			if len(buffer) <= i+1 {
				return errTCPAuthOption
			}
			if int(buffer[i+1]) == 0 {
				zap.L().Debug("Bad Packet Option", zap.String("Buffer", hex.Dump(buffer)))
				return errors.New("Invalid TCP Option Packet")
			}
			i = i + int(buffer[i+1])
			continue
		}

		if buffer[i] == TCPAuthenticationOption {
			return nil
		}
		return errTCPAuthOption

	}
	return errTCPAuthOption
}

// FixupIPHdrOnDataModify modifies the IP header fields and checksum
func (p *Packet) FixupIPHdrOnDataModify(old, new uint16) {
	// IP Header Processing
	// IP chekcsum fixup.
	p.ipHdr.ipChecksum = incCsum16(p.ipHdr.ipChecksum, old, new)
	// Update IP Total Length.
	p.ipHdr.ipTotalLength = p.ipHdr.ipTotalLength + new - old

	if p.ipHdr.version == V6 {
		binary.BigEndian.PutUint16(p.ipHdr.Buffer[ipv6PayloadLenPos:ipv6PayloadLenPos+2], p.ipHdr.ipTotalLength-uint16(p.ipHdr.ipHeaderLen))
	} else {
		binary.BigEndian.PutUint16(p.ipHdr.Buffer[ipv4LengthPos:ipv4LengthPos+2], p.ipHdr.ipTotalLength)
		binary.BigEndian.PutUint16(p.ipHdr.Buffer[ipv4ChecksumPos:ipv4ChecksumPos+2], p.ipHdr.ipChecksum)
	}
}

// TCPSequenceNumber return the initial sequence number
func (p *Packet) TCPSequenceNumber() uint32 {
	if p.ipHdr.ipProto != IPProtocolTCP {
		return 0
	}
	return p.tcpHdr.tcpSeq
}

// SetTCPSeq sets the TCP seq number
func (p *Packet) SetTCPSeq(seq uint32) {
	p.tcpHdr.tcpSeq = seq
	buffer := p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:]
	binary.BigEndian.PutUint32(buffer[tcpSeqPos:tcpSeqPos+4], p.tcpHdr.tcpSeq)
}

// IncreaseTCPSeq increases TCP seq number by incr
func (p *Packet) IncreaseTCPSeq(incr uint32) {
	p.SetTCPSeq(p.tcpHdr.tcpSeq + incr)
}

// DecreaseTCPSeq decreases TCP seq number by decr
func (p *Packet) DecreaseTCPSeq(decr uint32) {
	p.SetTCPSeq(p.tcpHdr.tcpSeq - decr)
}

// SetTCPAck sets the TCP ack number
func (p *Packet) SetTCPAck(ack uint32) {
	p.tcpHdr.tcpAck = ack
	buffer := p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:]
	binary.BigEndian.PutUint32(buffer[tcpAckPos:tcpAckPos+4], p.tcpHdr.tcpAck)
}

// IncreaseTCPAck increases TCP ack number by incr
func (p *Packet) IncreaseTCPAck(incr uint32) {
	p.SetTCPAck(p.tcpHdr.tcpAck + incr)
}

// DecreaseTCPAck decreases TCP ack number by decr
func (p *Packet) DecreaseTCPAck(decr uint32) {
	p.SetTCPAck(p.tcpHdr.tcpAck - decr)
}

// FixuptcpHdrOnTCPDataDetach modifies the TCP header fields and checksum
func (p *Packet) FixuptcpHdrOnTCPDataDetach(optionLength uint16) {

	// Update DataOffset
	buffer := p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:]
	p.tcpHdr.tcpDataOffset = p.tcpHdr.tcpDataOffset - uint8(optionLength/4)
	buffer[tcpDataOffsetPos] = p.tcpHdr.tcpDataOffset << 4
}

// tcpDataDetach splits the p.Buffer into p.Buffer (header + some options), p.tcpOptions (optionLength) and p.TCPData (dataLength)
func (p *Packet) tcpDataDetach(optionLength uint16, dataLength uint16) { //nolint
	p.ipHdr.Buffer = p.ipHdr.Buffer[:uint16(p.ipHdr.ipHeaderLen)+p.TCPDataStartBytes()-optionLength]
}

// TCPDataDetach performs the following:
//   - Removes all TCP data from Buffer to TCPData.
//   - Removes "optionLength" bytes of options from TCP header to tcpOptions
//   - Updates IP Hdr (lengths, checksums)
//   - Updates TCP header (checksums)
func (p *Packet) TCPDataDetach(optionLength uint16) {
	// Length
	dataLength := uint16(len(p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:])) - p.TCPDataStartBytes()

	// detach TCP data
	p.tcpDataDetach(optionLength, dataLength)

	// Process TCP Header fields and metadata
	p.FixuptcpHdrOnTCPDataDetach(optionLength)

	// Process IP Header fields
	p.FixupIPHdrOnDataModify(p.ipHdr.ipTotalLength, p.ipHdr.ipTotalLength-(dataLength+optionLength))

	p.UpdateTCPChecksum()
}

// FixuptcpHdrOnTCPDataAttach modifies the TCP header fields and checksum
func (p *Packet) FixuptcpHdrOnTCPDataAttach(tcpOptionsLen uint16) {
	buffer := p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:]
	numberOfOptions := tcpOptionsLen / 4

	// Modify the fields
	p.tcpHdr.tcpDataOffset = p.tcpHdr.tcpDataOffset + uint8(numberOfOptions)
	buffer[tcpDataOffsetPos] = p.tcpHdr.tcpDataOffset << 4

	// Modify the tcp header length
	p.tcpHdr.tcpTotalLength = uint16(len(p.ipHdr.Buffer[p.ipHdr.ipHeaderLen:]))
}

// L4FlowHash calculate a hash string based on the 4-tuple. It returns the cached
// value and does not re-calculate it. This leads to performance gains.
func (p *Packet) L4FlowHash() string {
	return p.l4flowhash
}

func (p *Packet) l4FlowHash() string {
	return p.ipHdr.sourceAddress.String() + ":" + p.ipHdr.destinationAddress.String() + ":" + strconv.Itoa(int(p.SourcePort())) + ":" + strconv.Itoa(int(p.DestPort()))
}

// L4ReverseFlowHash calculate a hash string based on the 4-tuple by reversing source and destination information
func (p *Packet) L4ReverseFlowHash() string {
	return p.ipHdr.destinationAddress.String() + ":" + p.ipHdr.sourceAddress.String() + ":" + strconv.Itoa(int(p.DestPort())) + ":" + strconv.Itoa(int(p.SourcePort()))
}

// SourcePortHash calculates a hash based on dest ip/port for net packet and src ip/port for app packet.
func (p *Packet) SourcePortHash(stage uint64) string {
	if stage == PacketTypeNetwork {
		return p.L4ReverseFlowHash()
	}

	return p.L4FlowHash()
}

// ID returns the IP ID of the packet
func (p *Packet) ID() string {
	return strconv.Itoa(int(p.ipHdr.ipID))
}

//SourcePort -- returns the appropriate source port
func (p *Packet) SourcePort() uint16 {
	if p.ipHdr.ipProto == IPProtocolTCP {
		return p.tcpHdr.sourcePort
	}

	return p.udpHdr.sourcePort
}

//DestPort -- returns the appropriate destination port
func (p *Packet) DestPort() uint16 {
	if p.ipHdr.ipProto == IPProtocolTCP {
		return p.tcpHdr.destinationPort
	}

	return p.udpHdr.destinationPort
}

//SourceAddress returns the source IP
func (p *Packet) SourceAddress() net.IP {
	return p.ipHdr.sourceAddress
}

//DestinationAddress returns the destination address
func (p *Packet) DestinationAddress() net.IP {
	return p.ipHdr.destinationAddress
}

//TCPSeqNum returns tcp sequence number
func (p *Packet) TCPSeqNum() uint32 {
	return p.tcpHdr.tcpSeq
}

//TCPAckNum returns tcp ack number
func (p *Packet) TCPAckNum() uint32 {
	return p.tcpHdr.tcpAck
}

//IPProto returns the L4 protocol
func (p *Packet) IPProto() uint8 {
	return p.ipHdr.ipProto
}

//IPTotalLen returns the total length of the packet
func (p *Packet) IPTotalLen() uint16 {
	return p.ipHdr.ipTotalLength
}

//IPHeaderLen returns the ip header length
func (p *Packet) IPHeaderLen() uint8 {
	return p.ipHdr.ipHeaderLen
}

//GetBuffer returns the slice representing the buffer at offset specified
func (p *Packet) GetBuffer(offset int) []byte {
	return p.ipHdr.Buffer[offset:]
}

// IPversion returns the version of ip packet
func (p *Packet) IPversion() IPver {
	return p.ipHdr.version
}

//TestGetTCPPacket is used by other test code when they need to create a packet
func TestGetTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) *Packet {
	p := &Packet{}

	p.ipHdr.destinationAddress = dstIP
	p.tcpHdr.destinationPort = dstPort
	p.ipHdr.sourceAddress = srcIP
	p.tcpHdr.sourcePort = srcPort
	p.ipHdr.ipProto = IPProtocolTCP

	return p
}
