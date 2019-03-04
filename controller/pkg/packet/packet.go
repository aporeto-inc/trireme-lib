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

func (p *Packet) parseTCP(bytes []byte) {
	// TCP Header Processing
	tcpBuffer := bytes[p.IPHdr.IPHeaderLen:]

	p.TCPHdr.TCPChecksum = binary.BigEndian.Uint16(tcpBuffer[TCPChecksumPos : TCPChecksumPos+2])
	p.TCPHdr.SourcePort = binary.BigEndian.Uint16(tcpBuffer[tcpSourcePortPos : tcpSourcePortPos+2])
	p.TCPHdr.DestinationPort = binary.BigEndian.Uint16(tcpBuffer[tcpDestPortPos : tcpDestPortPos+2])
	p.TCPHdr.TCPAck = binary.BigEndian.Uint32(tcpBuffer[tcpAckPos : tcpAckPos+4])
	p.TCPHdr.TCPSeq = binary.BigEndian.Uint32(tcpBuffer[tcpSeqPos : tcpSeqPos+4])
	p.TCPHdr.tcpDataOffset = (tcpBuffer[tcpDataOffsetPos] & tcpDataOffsetMask) >> 4
	p.TCPHdr.TCPFlags = tcpBuffer[tcpFlagsOffsetPos]

	// Options and Payload that maybe added
	p.TCPHdr.tcpOptions = []byte{}
	p.TCPHdr.tcpData = []byte{}
}

func (p *Packet) parseUDP(bytes []byte) {
	// UDP Header Processing
	udpBuffer := bytes[p.IPHdr.IPHeaderLen:]

	p.UDPHdr.UDPChecksum = binary.BigEndian.Uint16(udpBuffer[UDPChecksumPos : UDPChecksumPos+2])
	p.UDPHdr.udpData = []byte{}

	p.UDPHdr.SourcePort = binary.BigEndian.Uint16(udpBuffer[udpSourcePortPos : udpSourcePortPos+2])
	p.UDPHdr.DestinationPort = binary.BigEndian.Uint16(udpBuffer[udpDestPortPos : udpDestPortPos+2])
}

func (p *Packet) parseIPv4Packet(bytes []byte, lengthValidate bool) (err error) {

	// IP Header Processing
	p.IPHdr.IPHeaderLen = (bytes[ipv4HdrLenPos] & ipv4HdrLenMask) * 4
	p.IPHdr.IPProto = bytes[ipv4ProtoPos]
	p.IPHdr.IPTotalLength = binary.BigEndian.Uint16(bytes[ipv4LengthPos : ipv4LengthPos+2])
	p.IPHdr.ipID = binary.BigEndian.Uint16(bytes[IPv4IDPos : IPv4IDPos+2])
	p.IPHdr.ipChecksum = binary.BigEndian.Uint16(bytes[ipv4ChecksumPos : ipv4ChecksumPos+2])
	p.IPHdr.SourceAddress = net.IP(bytes[ipv4SourceAddrPos : ipv4SourceAddrPos+4])
	p.IPHdr.DestinationAddress = net.IP(bytes[ipv4DestAddrPos : ipv4DestAddrPos+4])

	if p.IPHdr.IPHeaderLen != minIPv4HdrSize {
		return fmt.Errorf("packets with ip options not supported: hdrlen=%d", p.IPHdr.IPHeaderLen)
	}

	p.IPHdr.Buffer = bytes

	if lengthValidate && p.IPHdr.IPTotalLength != uint16(len(p.IPHdr.Buffer)) {
		if p.IPHdr.IPTotalLength < uint16(len(p.IPHdr.Buffer)) {
			p.IPHdr.Buffer = p.IPHdr.Buffer[:p.IPHdr.IPTotalLength]
		} else {
			return fmt.Errorf("stated ip packet length %d differs from bytes available %d", p.IPHdr.IPTotalLength, len(p.IPHdr.Buffer))
		}
	}

	// Some sanity checking for TCP.
	if p.IPHdr.IPProto == IPProtocolTCP {
		if p.IPHdr.IPTotalLength-uint16(p.IPHdr.IPHeaderLen) < minTCPIPPacketLen {
			return fmt.Errorf("tcp ip packet too small: hdrlen=%d", p.IPHdr.IPHeaderLen)
		}

		p.parseTCP(bytes)
	}

	// Some sanity checking for UDP.
	if p.IPHdr.IPProto == IPProtocolUDP {
		if p.IPHdr.IPTotalLength-uint16(p.IPHdr.IPHeaderLen) < minUDPIPPacketLen {
			return fmt.Errorf("udp ip packet too small: hdrlen=%d", p.IPHdr.IPHeaderLen)
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
	return p.TCPDataStartBytes() == uint16(len(p.IPHdr.Buffer[p.IPHdr.IPHeaderLen:]))
}

// GetTCPData returns any additional data in the packet
func (p *Packet) GetTCPData() []byte {
	return p.TCPHdr.tcpData
}

// GetUDPData return additional data in packet
func (p *Packet) GetUDPData() []byte {
	return p.IPHdr.Buffer[p.IPHdr.IPHeaderLen+UDPDataPos:]
}

// GetUDPDataStartBytes return start of UDP data
func (p *Packet) GetUDPDataStartBytes() uint16 {
	return UDPDataPos
}

// SetTCPData returns any additional data in the packet
func (p *Packet) SetTCPData(b []byte) {
	p.TCPHdr.tcpData = b
}

// SetUDPData sets additional data in the packet
func (p *Packet) SetUDPData(b []byte) {
	p.UDPHdr.udpData = b
}

// GetTCPOptions returns any additional options in the packet
func (p *Packet) GetTCPOptions() []byte {
	return p.TCPHdr.tcpOptions
}

// DropDetachedDataBytes removes any bytes that have been detached and stored locally
func (p *Packet) DropDetachedDataBytes() {
	p.TCPHdr.tcpData = []byte{}
}

// DropDetachedBytes removes any bytes that have been detached and stored locally
func (p *Packet) DropDetachedBytes() {

	p.TCPHdr.tcpOptions = []byte{}
	p.TCPHdr.tcpData = []byte{}
}

// TCPDataStartBytes provides the tcp data start offset in bytes
func (p *Packet) TCPDataStartBytes() uint16 {
	return uint16(p.TCPHdr.tcpDataOffset) * 4
}

// GetIPLength returns the IP length
func (p *Packet) GetIPLength() uint16 {
	return p.IPHdr.IPTotalLength
}

// Print is a print helper function
func (p *Packet) Print(context uint64) {

	if p.IPHdr.IPProto != IPProtocolTCP {
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

		if (p.TCPHdr.TCPFlags & TCPSynMask) == TCPSynMask {
			offset = 1
		}

		expAck := p.TCPHdr.TCPSeq + uint32(uint16(len(p.IPHdr.Buffer[p.IPHdr.IPHeaderLen:]))-p.TCPDataStartBytes()) + uint32(offset)
		ccsum := p.computeTCPChecksum()
		csumValidationStr := ""

		if p.TCPHdr.TCPChecksum != ccsum {
			csumValidationStr = "Bad Checksum"
		}

		buf += fmt.Sprintf("Packet: %5d %5s %25s %15s %5d %15s %5d %6s %20d %20d %6d %20d %20d %2d %5d %5d %12s\n",
			p.IPHdr.ipID,
			flagsToDir(p.context|context),
			flagsToStr(p.context|context),
			p.IPHdr.SourceAddress.To4().String(), p.TCPHdr.SourcePort,
			p.IPHdr.DestinationAddress.To4().String(), p.TCPHdr.DestinationPort,
			tcpFlagsToStr(p.TCPHdr.TCPFlags),
			p.TCPHdr.TCPSeq, p.TCPHdr.TCPAck, uint16(len(p.IPHdr.Buffer[p.IPHdr.IPHeaderLen:]))-p.TCPDataStartBytes(),
			expAck, expAck, p.TCPHdr.tcpDataOffset,
			p.TCPHdr.TCPChecksum, ccsum, csumValidationStr)
		print = true
	}

	if detailed {
		pktBytes := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 8, 0}
		pktBytes = append(pktBytes, p.IPHdr.Buffer...)
		pktBytes = append(pktBytes, p.TCPHdr.tcpOptions...)
		pktBytes = append(pktBytes, p.TCPHdr.tcpData...)
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
	pktBytes = append(pktBytes, p.IPHdr.Buffer...)
	pktBytes = append(pktBytes, p.TCPHdr.tcpOptions...)
	pktBytes = append(pktBytes, p.TCPHdr.tcpData...)
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
	return p.IPHdr.Buffer[uint16(p.IPHdr.IPHeaderLen)+p.TCPDataStartBytes():]
}

// CheckTCPAuthenticationOption ensures authentication option exists at the offset provided
func (p *Packet) CheckTCPAuthenticationOption(iOptionLength int) (err error) {

	tcpDataStart := p.TCPDataStartBytes()

	if tcpDataStart <= minTCPIPPacketLen {
		return errTCPAuthOption
	}

	optionLength := uint16(iOptionLength)
	buffer := p.IPHdr.Buffer[p.IPHdr.IPHeaderLen:]
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
	p.IPHdr.ipChecksum = incCsum16(p.IPHdr.ipChecksum, old, new)
	// Update IP Total Length.
	p.IPHdr.IPTotalLength = p.IPHdr.IPTotalLength + new - old

	binary.BigEndian.PutUint16(p.IPHdr.Buffer[ipv4LengthPos:ipv4LengthPos+2], p.IPHdr.IPTotalLength)
	binary.BigEndian.PutUint16(p.IPHdr.Buffer[ipv4ChecksumPos:ipv4ChecksumPos+2], p.IPHdr.ipChecksum)
}

// IncreaseTCPSeq increases TCP seq number by incr
func (p *Packet) IncreaseTCPSeq(incr uint32) {
	buffer := p.IPHdr.Buffer[p.IPHdr.IPHeaderLen:]
	p.TCPHdr.TCPSeq = p.TCPHdr.TCPSeq + incr
	binary.BigEndian.PutUint32(buffer[tcpSeqPos:tcpSeqPos+4], p.TCPHdr.TCPSeq)
}

// DecreaseTCPSeq decreases TCP seq number by decr
func (p *Packet) DecreaseTCPSeq(decr uint32) {
	buffer := p.IPHdr.Buffer[p.IPHdr.IPHeaderLen:]
	p.TCPHdr.TCPSeq = p.TCPHdr.TCPSeq - decr
	binary.BigEndian.PutUint32(buffer[tcpSeqPos:tcpSeqPos+4], p.TCPHdr.TCPSeq)
}

// IncreaseTCPAck increases TCP ack number by incr
func (p *Packet) IncreaseTCPAck(incr uint32) {
	buffer := p.IPHdr.Buffer[p.IPHdr.IPHeaderLen:]
	p.TCPHdr.TCPAck = p.TCPHdr.TCPAck + incr
	binary.BigEndian.PutUint32(buffer[tcpAckPos:tcpAckPos+4], p.TCPHdr.TCPAck)
}

// DecreaseTCPAck decreases TCP ack number by decr
func (p *Packet) DecreaseTCPAck(decr uint32) {
	buffer := p.IPHdr.Buffer[p.IPHdr.IPHeaderLen:]
	p.TCPHdr.TCPAck = p.TCPHdr.TCPAck - decr
	binary.BigEndian.PutUint32(buffer[tcpAckPos:tcpAckPos+4], p.TCPHdr.TCPAck)
}

// FixupTCPHdrOnTCPDataDetach modifies the TCP header fields and checksum
func (p *Packet) FixupTCPHdrOnTCPDataDetach(dataLength uint16, optionLength uint16) {

	// Update DataOffset
	buffer := p.IPHdr.Buffer[p.IPHdr.IPHeaderLen:]
	p.TCPHdr.tcpDataOffset = p.TCPHdr.tcpDataOffset - uint8(optionLength/4)
	buffer[tcpDataOffsetPos] = p.TCPHdr.tcpDataOffset << 4
}

// tcpDataDetach splits the p.Buffer into p.Buffer (header + some options), p.tcpOptions (optionLength) and p.TCPData (dataLength)
func (p *Packet) tcpDataDetach(optionLength uint16, dataLength uint16) (err error) {

	buffer := p.IPHdr.Buffer[p.IPHdr.IPHeaderLen:]
	// Setup buffer for Options, Data and reduce the original buffer
	if dataLength != 0 {
		p.TCPHdr.tcpData = buffer[p.TCPDataStartBytes():]
	}

	if optionLength != 0 {
		p.TCPHdr.tcpOptions = buffer[p.TCPDataStartBytes()-optionLength : p.TCPDataStartBytes()]
	}

	p.IPHdr.Buffer = p.IPHdr.Buffer[:uint16(p.IPHdr.IPHeaderLen)+p.TCPDataStartBytes()-optionLength]

	return
}

// TCPDataDetach performs the following:
//   - Removes all TCP data from Buffer to TCPData.
//   - Removes "optionLength" bytes of options from TCP header to tcpOptions
//   - Updates IP Hdr (lengths, checksums)
//   - Updates TCP header (checksums)
func (p *Packet) TCPDataDetach(optionLength uint16) (err error) {

	// Length
	dataLength := uint16(len(p.IPHdr.Buffer[p.IPHdr.IPHeaderLen:])) - p.TCPDataStartBytes()

	// detach TCP data
	if err = p.tcpDataDetach(optionLength, dataLength); err != nil {
		zap.L().Debug(fmt.Sprintf("tcp data detach failed: %s: optionlength=%d optionlength=%d", err, optionLength, dataLength))
		return errTCPPacketCorrupt
	}

	// Process TCP Header fields and metadata
	p.FixupTCPHdrOnTCPDataDetach(dataLength, optionLength)

	// Process IP Header fields
	p.FixupIPHdrOnDataModify(p.IPHdr.IPTotalLength, p.IPHdr.IPTotalLength-(dataLength+optionLength))
	return
}

// FixupTCPHdrOnTCPDataAttach modifies the TCP header fields and checksum
func (p *Packet) FixupTCPHdrOnTCPDataAttach(tcpOptions []byte, tcpData []byte) {
	buffer := p.IPHdr.Buffer[p.IPHdr.IPHeaderLen:]
	numberOfOptions := len(tcpOptions) / 4

	// Modify the fields
	p.TCPHdr.tcpDataOffset = p.TCPHdr.tcpDataOffset + uint8(numberOfOptions)
	binary.BigEndian.PutUint16(buffer[TCPChecksumPos:TCPChecksumPos+2], p.TCPHdr.TCPChecksum)
	buffer[tcpDataOffsetPos] = p.TCPHdr.tcpDataOffset << 4
}

// tcpDataAttach splits the p.Buffer into p.Buffer (header + some options), p.tcpOptions (optionLength) and p.TCPData (dataLength)
func (p *Packet) tcpDataAttach(options []byte, data []byte) (err error) {

	if p.TCPDataStartBytes() != uint16(len(p.IPHdr.Buffer[p.IPHdr.IPHeaderLen:])) && len(options) != 0 {
		return fmt.Errorf("cannot insert options with existing data: optionlength=%d, iptotallength=%d", len(options), p.IPHdr.IPTotalLength)
	}

	p.TCPHdr.tcpOptions = append(p.TCPHdr.tcpOptions, options...)
	p.TCPHdr.tcpData = data

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
	p.FixupIPHdrOnDataModify(p.IPHdr.IPTotalLength, p.IPHdr.IPTotalLength+packetLenIncrease)

	// TCP Header Processing
	p.FixupTCPHdrOnTCPDataAttach(tcpOptions, tcpData)

	return
}

// L4FlowHash calculate a hash string based on the 4-tuple
func (p *Packet) L4FlowHash() string {
	return p.IPHdr.SourceAddress.String() + ":" + p.IPHdr.DestinationAddress.String() + ":" + strconv.Itoa(int(p.SourcePort())) + ":" + strconv.Itoa(int(p.DestPort()))
}

// L4ReverseFlowHash calculate a hash string based on the 4-tuple by reversing source and destination information
func (p *Packet) L4ReverseFlowHash() string {
	return p.IPHdr.DestinationAddress.String() + ":" + p.IPHdr.SourceAddress.String() + ":" + strconv.Itoa(int(p.DestPort())) + ":" + strconv.Itoa(int(p.SourcePort()))
}

// SourcePortHash calculates a hash based on dest ip/port for net packet and src ip/port for app packet.
func (p *Packet) SourcePortHash(stage uint64) string {
	if stage == PacketTypeNetwork {
		return p.IPHdr.DestinationAddress.String() + ":" + strconv.Itoa(int(p.DestPort()))
	}

	return p.IPHdr.SourceAddress.String() + ":" + strconv.Itoa(int(p.SourcePort()))
}

// ID returns the IP ID of the packet
func (p *Packet) ID() string {
	return strconv.Itoa(int(p.IPHdr.ipID))
}

//TCPOptionLength returns the length of tcpoptions
func (p *Packet) TCPOptionLength() int {
	return len(p.TCPHdr.tcpOptions)
}

//TCPDataLength -- returns the length of tcp options
func (p *Packet) TCPDataLength() int {
	return len(p.TCPHdr.tcpData)
}

//SourcePort -- returns the appropriate source port
func (p *Packet) SourcePort() uint16 {
	if p.IPHdr.IPProto == IPProtocolTCP {
		return p.TCPHdr.SourcePort
	}

	return p.UDPHdr.SourcePort
}

//DestPort -- returns the appropriate destination port
func (p *Packet) DestPort() uint16 {
	if p.IPHdr.IPProto == IPProtocolTCP {
		return p.TCPHdr.DestinationPort
	}

	return p.UDPHdr.DestinationPort
}
