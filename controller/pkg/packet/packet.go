// Package packet support for TCP/IP packet manipulations
// needed by the Aporeto infrastructure.
package packet

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"

	"go.uber.org/zap"
)

var (
	// PacketLogLevel determines if packet logging is turned on
	PacketLogLevel bool

	// printCount prints the debug header for packets every few lines that it prints
	printCount int

	// Debugging for Packets
	debugContext    uint64
	debugContextApp uint64
	debugContextNet uint64
)

var errTCPPacketCorrupt = errors.New("TCP Packet corrupt")
var errTCPAuthOption = errors.New("tcp authentication option not found")
var errTCPShort = errors.New("tcp packet is less than minimum 20 bytes")
var errNonTCPUDPPacket = errors.New("packet is neither TCP nor UDP")

func init() {
	PacketLogLevel = false
	debugContext = 0
	debugContextApp = 0 //PacketStageIncoming
	debugContextNet = 0 //PacketStageOutgoing

	cbuf := fmt.Sprintf(" Network:0x%04x Application:0x%04x",
		PacketTypeNetwork,
		PacketTypeApplication)

	fbuf := fmt.Sprintf(" Incoming:0x%04x Auth:0x%04x Service:0x%04x Outgoing:0x%04x",
		PacketStageIncoming,
		PacketStageAuth,
		PacketStageService,
		PacketStageOutgoing)

	flag.Uint64Var(&debugContext, "debug-packet-context", 0, "packet contexts to debug -"+cbuf+fbuf)
	flag.Uint64Var(&debugContextApp, "debug-packet-context-app", 0, "app packet contexts to debug -"+fbuf)
	flag.Uint64Var(&debugContextNet, "debug-packet-context-net", 0, "net packet contexts to debug -"+fbuf)
}

// New returns a pointer to Packet structure built from the
// provided bytes buffer which is expected to contain valid TCP/IP
// packet bytes.
func New(context uint64, bytes []byte, mark string, lengthValidate bool) (packet *Packet, err error) {

	var p Packet

	// Get the mark value
	p.Mark = mark

	// Set the context
	p.context = context

	if bytes[ipv4HdrLenPos]&ipv4ProtoMask == 0x40 {
		return &p, p.parseIPv4Packet(bytes, lengthValidate)
	}

	return p.parseIPv6Packet()
}

func (p *Packet) parseTCP(bytes []byte) error {
	// TCP Header Processing
	tcpBuffer := bytes[p.IpHdr.IPHeaderLen:]

	p.TcpHdr.TCPChecksum = binary.BigEndian.Uint16(tcpBuffer[TCPChecksumPos : TCPChecksumPos+2])
	p.TcpHdr.SourcePort = binary.BigEndian.Uint16(tcpBuffer[tcpSourcePortPos : tcpSourcePortPos+2])
	p.TcpHdr.DestinationPort = binary.BigEndian.Uint16(tcpBuffer[tcpDestPortPos : tcpDestPortPos+2])
	p.TcpHdr.TCPAck = binary.BigEndian.Uint32(tcpBuffer[tcpAckPos : tcpAckPos+4])
	p.TcpHdr.TCPSeq = binary.BigEndian.Uint32(tcpBuffer[tcpSeqPos : tcpSeqPos+4])
	p.TcpHdr.tcpDataOffset = (tcpBuffer[tcpDataOffsetPos] & tcpDataOffsetMask) >> 4
	p.TcpHdr.TCPFlags = tcpBuffer[tcpFlagsOffsetPos]

	// Options and Payload that maybe added
	p.TcpHdr.tcpOptions = []byte{}
	p.TcpHdr.tcpData = []byte{}

	return nil
}

func (p *Packet) parseUDP(bytes []byte) {
	// UDP Header Processing
	udpBuffer := bytes[p.IpHdr.IPHeaderLen:]

	p.UdpHdr.UDPChecksum = binary.BigEndian.Uint16(udpBuffer[UDPChecksumPos : UDPChecksumPos+2])
	p.UdpHdr.udpData = []byte{}

	p.UdpHdr.SourcePort = binary.BigEndian.Uint16(udpBuffer[udpSourcePortPos : udpSourcePortPos+2])
	p.UdpHdr.DestinationPort = binary.BigEndian.Uint16(udpBuffer[udpDestPortPos : udpDestPortPos+2])
}

func (p *Packet) parseIPv4Packet(bytes []byte, lengthValidate bool) (err error) {

	// IP Header Processing
	p.IpHdr.IPHeaderLen = (bytes[ipv4HdrLenPos] & ipv4HdrLenMask) * 4
	p.IpHdr.IPProto = bytes[ipv4ProtoPos]
	p.IpHdr.IPTotalLength = binary.BigEndian.Uint16(bytes[ipv4LengthPos : ipv4LengthPos+2])
	p.IpHdr.ipID = binary.BigEndian.Uint16(bytes[IPv4IDPos : IPv4IDPos+2])
	p.IpHdr.ipChecksum = binary.BigEndian.Uint16(bytes[ipv4ChecksumPos : ipv4ChecksumPos+2])
	p.IpHdr.SourceAddress = net.IP(bytes[ipv4SourceAddrPos : ipv4SourceAddrPos+4])
	p.IpHdr.DestinationAddress = net.IP(bytes[ipv4DestAddrPos : ipv4DestAddrPos+4])

	if p.IpHdr.IPHeaderLen != minIPv4HdrSize {
		return fmt.Errorf("packets with ip options not supported: hdrlen=%d", p.IpHdr.IPHeaderLen)
	}

	p.IpHdr.Buffer = bytes

	if lengthValidate && p.IpHdr.IPTotalLength != uint16(len(p.IpHdr.Buffer)) {
		if p.IpHdr.IPTotalLength < uint16(len(p.IpHdr.Buffer)) {
			p.IpHdr.Buffer = p.IpHdr.Buffer[:p.IpHdr.IPTotalLength]
		} else {
			return fmt.Errorf("stated ip packet length %d differs from bytes available %d", p.IpHdr.IPTotalLength, len(p.IpHdr.Buffer))
		}
	}

	// Some sanity checking for TCP.
	if p.IpHdr.IPProto == IPProtocolTCP {
		if p.IpHdr.IPTotalLength-uint16(p.IpHdr.IPHeaderLen) < minTCPIPPacketLen {
			return fmt.Errorf("tcp ip packet too small: hdrlen=%d", p.IpHdr.IPHeaderLen)
		}

		p.parseTCP(bytes)
	}

	// Some sanity checking for UDP.
	if p.IpHdr.IPProto == IPProtocolUDP {
		if p.IpHdr.IPTotalLength-uint16(p.IpHdr.IPHeaderLen) < minUDPIPPacketLen {
			return fmt.Errorf("udp ip packet too small: hdrlen=%d", p.IpHdr.IPHeaderLen)
		}

		p.parseUDP(bytes)
	}

	return nil
}

func (p *Packet) parseIPv6Packet() (packet *Packet, err error) {
	return nil, nil
}

// IsEmptyTCPPayload returns the TCP data offset
func (p *Packet) IsEmptyTCPPayload() bool {
	return p.TCPDataStartBytes() == uint16(len(p.IpHdr.Buffer[p.IpHdr.IPHeaderLen:]))
}

// GetTCPData returns any additional data in the packet
func (p *Packet) GetTCPData() []byte {
	return p.TcpHdr.tcpData
}

// GetUDPData return additional data in packet
func (p *Packet) GetUDPData() []byte {
	return p.IpHdr.Buffer[p.IpHdr.IPHeaderLen+UDPDataPos:]
}

// GetUDPDataStartBytes return start of UDP data
func (p *Packet) GetUDPDataStartBytes() uint16 {
	return UDPDataPos
}

// SetTCPData returns any additional data in the packet
func (p *Packet) SetTCPData(b []byte) {
	p.TcpHdr.tcpData = b
}

// SetUDPData sets additional data in the packet
func (p *Packet) SetUDPData(b []byte) {
	p.UdpHdr.udpData = b
}

// GetTCPOptions returns any additional options in the packet
func (p *Packet) GetTCPOptions() []byte {
	return p.TcpHdr.tcpOptions
}

// DropDetachedDataBytes removes any bytes that have been detached and stored locally
func (p *Packet) DropDetachedDataBytes() {
	p.TcpHdr.tcpData = []byte{}
}

// DropDetachedBytes removes any bytes that have been detached and stored locally
func (p *Packet) DropDetachedBytes() {

	p.TcpHdr.tcpOptions = []byte{}
	p.TcpHdr.tcpData = []byte{}
}

// TCPDataStartBytes provides the tcp data start offset in bytes
func (p *Packet) TCPDataStartBytes() uint16 {
	return uint16(p.TcpHdr.tcpDataOffset) * 4
}

// GetIPLength returns the IP length
func (p *Packet) GetIPLength() uint16 {
	return p.IpHdr.IPTotalLength
}

// Print is a print helper function
func (p *Packet) Print(context uint64) {

	if p.IpHdr.IPProto != IPProtocolTCP {
		return
	}

	dbgContext := context | p.context
	logPkt := false
	detailed := false

	if (PacketLogLevel || context == 0) || (dbgContext&PacketTypeApplication != 0 && dbgContext&debugContextApp != 0) || (dbgContext&PacketTypeNetwork != 0 && dbgContext&debugContextNet != 0) {
		logPkt = true
		detailed = true
	} else if dbgContext&debugContext != 0 {
		logPkt = true
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

		if (p.TcpHdr.TCPFlags & TCPSynMask) == TCPSynMask {
			offset = 1
		}

		expAck := p.TcpHdr.TCPSeq + uint32(uint16(len(p.IpHdr.Buffer[p.IpHdr.IPHeaderLen:]))-p.TCPDataStartBytes()) + uint32(offset)
		ccsum := p.computeTCPChecksum()
		csumValidationStr := ""

		if p.TcpHdr.TCPChecksum != ccsum {
			csumValidationStr = "Bad Checksum"
		}

		buf += fmt.Sprintf("Packet: %5d %5s %25s %15s %5d %15s %5d %6s %20d %20d %6d %20d %20d %2d %5d %5d %12s\n",
			p.IpHdr.ipID,
			flagsToDir(p.context|context),
			flagsToStr(p.context|context),
			p.IpHdr.SourceAddress.To4().String(), p.TcpHdr.SourcePort,
			p.IpHdr.DestinationAddress.To4().String(), p.TcpHdr.DestinationPort,
			tcpFlagsToStr(p.TcpHdr.TCPFlags),
			p.TcpHdr.TCPSeq, p.TcpHdr.TCPAck, uint16(len(p.IpHdr.Buffer[p.IpHdr.IPHeaderLen:]))-p.TCPDataStartBytes(),
			expAck, expAck, p.TcpHdr.tcpDataOffset,
			p.TcpHdr.TCPChecksum, ccsum, csumValidationStr)
		print = true
	}

	if detailed {
		pktBytes := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 8, 0}
		pktBytes = append(pktBytes, p.IpHdr.Buffer...)
		pktBytes = append(pktBytes, p.TcpHdr.tcpOptions...)
		pktBytes = append(pktBytes, p.TcpHdr.tcpData...)
		buf += fmt.Sprintf("%s\n", hex.Dump(pktBytes))
		print = true
	}

	if print {
		zap.L().Debug(buf)
	}
}

//GetBytes returns the bytes in the packet. It consolidates in case of changes as well
func (p *Packet) GetBytes() []byte {

	pktBytes := []byte{}
	pktBytes = append(pktBytes, p.IpHdr.Buffer...)
	pktBytes = append(pktBytes, p.TcpHdr.tcpOptions...)
	pktBytes = append(pktBytes, p.TcpHdr.tcpData...)
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
	return p.IpHdr.Buffer[uint16(p.IpHdr.IPHeaderLen)+p.TCPDataStartBytes():]
}

// CheckTCPAuthenticationOption ensures authentication option exists at the offset provided
func (p *Packet) CheckTCPAuthenticationOption(iOptionLength int) (err error) {

	tcpDataStart := p.TCPDataStartBytes()

	if tcpDataStart <= minTCPIPPacketLen {
		return errTCPAuthOption
	}

	optionLength := uint16(iOptionLength)
	buffer := p.IpHdr.Buffer[p.IpHdr.IPHeaderLen:]
	// Our option was not found in the right place. We don't do anything
	// for this packet.
	if buffer[tcpDataStart-optionLength] != TCPAuthenticationOption {
		return errTCPAuthOption
	}

	return
}

// FixupIPHdrOnDataModify modifies the IP header fields and checksum
func (p *Packet) FixupIPHdrOnDataModify(old, new uint16) {
	// IP Header Processing
	// IP chekcsum fixup.
	p.IpHdr.ipChecksum = incCsum16(p.IpHdr.ipChecksum, old, new)
	// Update IP Total Length.
	p.IpHdr.IPTotalLength = p.IpHdr.IPTotalLength + new - old

	binary.BigEndian.PutUint16(p.IpHdr.Buffer[ipv4LengthPos:ipv4LengthPos+2], p.IpHdr.IPTotalLength)
	binary.BigEndian.PutUint16(p.IpHdr.Buffer[ipv4ChecksumPos:ipv4ChecksumPos+2], p.IpHdr.ipChecksum)
}

// IncreaseTCPSeq increases TCP seq number by incr
func (p *Packet) IncreaseTCPSeq(incr uint32) {
	buffer := p.IpHdr.Buffer[p.IpHdr.IPHeaderLen:]
	p.TcpHdr.TCPSeq = p.TcpHdr.TCPSeq + incr
	binary.BigEndian.PutUint32(buffer[tcpSeqPos:tcpSeqPos+4], p.TcpHdr.TCPSeq)
}

// DecreaseTCPSeq decreases TCP seq number by decr
func (p *Packet) DecreaseTCPSeq(decr uint32) {
	buffer := p.IpHdr.Buffer[p.IpHdr.IPHeaderLen:]
	p.TcpHdr.TCPSeq = p.TcpHdr.TCPSeq - decr
	binary.BigEndian.PutUint32(buffer[tcpSeqPos:tcpSeqPos+4], p.TcpHdr.TCPSeq)
}

// IncreaseTCPAck increases TCP ack number by incr
func (p *Packet) IncreaseTCPAck(incr uint32) {
	buffer := p.IpHdr.Buffer[p.IpHdr.IPHeaderLen:]
	p.TcpHdr.TCPAck = p.TcpHdr.TCPAck + incr
	binary.BigEndian.PutUint32(buffer[tcpAckPos:tcpAckPos+4], p.TcpHdr.TCPAck)
}

// DecreaseTCPAck decreases TCP ack number by decr
func (p *Packet) DecreaseTCPAck(decr uint32) {
	buffer := p.IpHdr.Buffer[p.IpHdr.IPHeaderLen:]
	p.TcpHdr.TCPAck = p.TcpHdr.TCPAck - decr
	binary.BigEndian.PutUint32(buffer[tcpAckPos:tcpAckPos+4], p.TcpHdr.TCPAck)
}

// FixupTCPHdrOnTCPDataDetach modifies the TCP header fields and checksum
func (p *Packet) FixupTCPHdrOnTCPDataDetach(dataLength uint16, optionLength uint16) {

	// Update DataOffset
	buffer := p.IpHdr.Buffer[p.IpHdr.IPHeaderLen:]
	p.TcpHdr.tcpDataOffset = p.TcpHdr.tcpDataOffset - uint8(optionLength/4)
	buffer[tcpDataOffsetPos] = p.TcpHdr.tcpDataOffset << 4
}

// tcpDataDetach splits the p.Buffer into p.Buffer (header + some options), p.tcpOptions (optionLength) and p.TCPData (dataLength)
func (p *Packet) tcpDataDetach(optionLength uint16, dataLength uint16) (err error) {

	buffer := p.IpHdr.Buffer[p.IpHdr.IPHeaderLen:]
	// Setup buffer for Options, Data and reduce the original buffer
	if dataLength != 0 {
		p.TcpHdr.tcpData = buffer[p.TCPDataStartBytes():]
	}

	if optionLength != 0 {
		p.TcpHdr.tcpOptions = buffer[p.TCPDataStartBytes()-optionLength : p.TCPDataStartBytes()]
	}

	p.IpHdr.Buffer = p.IpHdr.Buffer[:uint16(p.IpHdr.IPHeaderLen)+p.TCPDataStartBytes()-optionLength]

	return
}

// TCPDataDetach performs the following:
//   - Removes all TCP data from Buffer to TCPData.
//   - Removes "optionLength" bytes of options from TCP header to tcpOptions
//   - Updates IP Hdr (lengths, checksums)
//   - Updates TCP header (checksums)
func (p *Packet) TCPDataDetach(optionLength uint16) (err error) {

	// Length
	dataLength := uint16(len(p.IpHdr.Buffer[p.IpHdr.IPHeaderLen:])) - p.TCPDataStartBytes()

	// detach TCP data
	if err = p.tcpDataDetach(optionLength, dataLength); err != nil {
		zap.L().Debug(fmt.Sprintf("tcp data detach failed: %s: optionlength=%d optionlength=%d", err, optionLength, dataLength))
		return errTCPPacketCorrupt
	}

	// Process TCP Header fields and metadata
	p.FixupTCPHdrOnTCPDataDetach(dataLength, optionLength)

	// Process IP Header fields
	p.FixupIPHdrOnDataModify(p.IpHdr.IPTotalLength, p.IpHdr.IPTotalLength-(dataLength+optionLength))
	return
}

// FixupTCPHdrOnTCPDataAttach modifies the TCP header fields and checksum
func (p *Packet) FixupTCPHdrOnTCPDataAttach(tcpOptions []byte, tcpData []byte) {
	buffer := p.IpHdr.Buffer[p.IpHdr.IPHeaderLen:]
	numberOfOptions := len(tcpOptions) / 4

	// Modify the fields
	p.TcpHdr.tcpDataOffset = p.TcpHdr.tcpDataOffset + uint8(numberOfOptions)
	binary.BigEndian.PutUint16(buffer[TCPChecksumPos:TCPChecksumPos+2], p.TcpHdr.TCPChecksum)
	buffer[tcpDataOffsetPos] = p.TcpHdr.tcpDataOffset << 4
}

// tcpDataAttach splits the p.Buffer into p.Buffer (header + some options), p.tcpOptions (optionLength) and p.TCPData (dataLength)
func (p *Packet) tcpDataAttach(options []byte, data []byte) (err error) {

	if p.TCPDataStartBytes() != uint16(len(p.IpHdr.Buffer[p.IpHdr.IPHeaderLen:])) && len(options) != 0 {
		return fmt.Errorf("cannot insert options with existing data: optionlength=%d, iptotallength=%d", len(options), p.IpHdr.IPTotalLength)
	}

	p.TcpHdr.tcpOptions = append(p.TcpHdr.tcpOptions, options...)
	p.TcpHdr.tcpData = data

	return
}

// TCPDataAttach modifies the TCP and IP header fields and checksum
func (p *Packet) TCPDataAttach(tcpOptions []byte, tcpData []byte) (err error) {

	if err = p.tcpDataAttach(tcpOptions, tcpData); err != nil {
		return fmt.Errorf("tcp data attachment failed: %s", err)
	}

	// We are increasing tcpOptions by 1 32-bit word. We are always adding
	// our option last.
	packetLenIncrease := uint16(len(tcpData) + len(tcpOptions))

	// IP Header Processing
	p.FixupIPHdrOnDataModify(p.IpHdr.IPTotalLength, p.IpHdr.IPTotalLength+packetLenIncrease)

	// TCP Header Processing
	p.FixupTCPHdrOnTCPDataAttach(tcpOptions, tcpData)

	return
}

// L4FlowHash calculate a hash string based on the 4-tuple
func (p *Packet) L4FlowHash() string {
	return p.IpHdr.SourceAddress.String() + ":" + p.IpHdr.DestinationAddress.String() + ":" + strconv.Itoa(int(p.SourcePort())) + ":" + strconv.Itoa(int(p.DestPort()))
}

// L4ReverseFlowHash calculate a hash string based on the 4-tuple by reversing source and destination information
func (p *Packet) L4ReverseFlowHash() string {
	return p.IpHdr.DestinationAddress.String() + ":" + p.IpHdr.SourceAddress.String() + ":" + strconv.Itoa(int(p.DestPort())) + ":" + strconv.Itoa(int(p.SourcePort()))
}

// SourcePortHash calculates a hash based on dest ip/port for net packet and src ip/port for app packet.
func (p *Packet) SourcePortHash(stage uint64) string {
	if stage == PacketTypeNetwork {
		return p.IpHdr.DestinationAddress.String() + ":" + strconv.Itoa(int(p.DestPort()))
	}

	return p.IpHdr.SourceAddress.String() + ":" + strconv.Itoa(int(p.SourcePort()))
}

// ID returns the IP ID of the packet
func (p *Packet) ID() string {
	return strconv.Itoa(int(p.IpHdr.ipID))
}

//TCPOptionLength returns the length of tcpoptions
func (p *Packet) TCPOptionLength() int {
	return len(p.TcpHdr.tcpOptions)
}

//TCPDataLength -- returns the length of tcp options
func (p *Packet) TCPDataLength() int {
	return len(p.TcpHdr.tcpData)
}

//SourcePort -- returns the appropriate source port
func (p *Packet) SourcePort() uint16 {
	if p.IpHdr.IPProto == IPProtocolTCP {
		return p.TcpHdr.SourcePort
	}

	return p.UdpHdr.SourcePort
}

//DestPort -- returns the appropriate destination port
func (p *Packet) DestPort() uint16 {
	if p.IpHdr.IPProto == IPProtocolTCP {
		return p.TcpHdr.DestinationPort
	}

	return p.UdpHdr.DestinationPort
}
