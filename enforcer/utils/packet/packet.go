// Package packet support for TCP/IP packet manipulations
// needed by the Aporeto infrastructure.
package packet

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"strconv"

	log "github.com/Sirupsen/logrus"
)

var (
	// printCount prints the debug header for packets every few lines that it prints
	printCount int

	// Debugging for Packets
	debugContext    uint64
	debugContextApp uint64
	debugContextNet uint64
)

func init() {
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
func New(context uint64, bytes []byte, mark string) (packet *Packet, err error) {

	var p Packet

	// Buffer Setup
	p.Buffer = bytes

	// Get the mark value
	p.Mark = mark
	p.L4TCPPacket = &TCPPacket{optionsMap: make(map[TCPOptions]tcpOptionsFormat)}
	// Options and Payload that maybe added
	p.L4TCPPacket.tcpOptions = []byte{}
	p.L4TCPPacket.tcpData = []byte{}

	// IP Header Processing
	p.ipHeaderLen = bytes[ipHdrLenPos] & ipHdrLenMask
	p.IPProto = bytes[ipProtoPos]
	p.IPTotalLength = binary.BigEndian.Uint16(bytes[ipLengthPos : ipLengthPos+2])
	p.ipID = binary.BigEndian.Uint16(bytes[IPIDPos : IPIDPos+2])
	p.ipChecksum = binary.BigEndian.Uint16(bytes[ipChecksumPos : ipChecksumPos+2])
	p.SourceAddress = net.IP(bytes[ipSourceAddrPos : ipSourceAddrPos+4])
	p.DestinationAddress = net.IP(bytes[ipDestAddrPos : ipDestAddrPos+4])

	// Some sanity checking...
	if p.IPTotalLength < minIPPacketLen {
		log.WithFields(log.Fields{
			"package":        "packet",
			"ipHeaderLength": p.ipHeaderLen,
		}).Debug("IP Packet too small")

		return nil, fmt.Errorf("IP Packet too small")
	}

	if p.ipHeaderLen != minIPHdrWords {
		log.WithFields(log.Fields{
			"package":        "packet",
			"ipHeaderLength": p.ipHeaderLen,
		}).Debug("Packets with IP options not supported")

		return nil, fmt.Errorf("Packets with IP options not supported (hdrlen=%d)", p.ipHeaderLen)
	}

	if p.IPTotalLength != uint16(len(p.Buffer)) {
		if p.IPTotalLength < uint16(len(p.Buffer)) {
			p.Buffer = p.Buffer[:p.IPTotalLength]
		} else {
			log.WithFields(log.Fields{
				"package":       "packet",
				"IPTotalLength": p.IPTotalLength,
				"bufferLength":  len(p.Buffer),
			}).Debug("Stated IP packet length differs from bytes available")
			return nil, fmt.Errorf("Stated IP packet length (%d) differs from bytes available (%d)", p.IPTotalLength, len(p.Buffer))
		}
	}

	// TCP Header Processing
	p.l4BeginPos = minIPHdrSize
	p.L4TCPPacket.TCPChecksum = binary.BigEndian.Uint16(bytes[TCPChecksumPos : TCPChecksumPos+2])
	p.L4TCPPacket.SourcePort = binary.BigEndian.Uint16(bytes[tcpSourcePortPos : tcpSourcePortPos+2])
	p.L4TCPPacket.DestinationPort = binary.BigEndian.Uint16(bytes[tcpDestPortPos : tcpDestPortPos+2])
	p.L4TCPPacket.TCPAck = binary.BigEndian.Uint32(bytes[tcpAckPos : tcpAckPos+4])
	p.L4TCPPacket.TCPSeq = binary.BigEndian.Uint32(bytes[tcpSeqPos : tcpSeqPos+4])
	p.L4TCPPacket.tcpDataOffset = (bytes[tcpDataOffsetPos] & tcpDataOffsetMask) >> 4

	p.L4TCPPacket.TCPFlags = bytes[tcpFlagsOffsetPos]
	if p.L4TCPPacket.tcpDataOffset > 5 {
		p.parseTCPOption(bytes)
	}
	p.context = context
	p.L4TCPPacket.tcpData = append(p.L4TCPPacket.tcpData, bytes[(p.ipHeaderLen*4+p.L4TCPPacket.tcpDataOffset*4):p.IPTotalLength]...)
	//20 is the fixed length portion of the tcp header
	//p.L4TCPPacket.tcpOptions = append(p.L4TCPPacket.tcpOptions, bytes[TCPOptionPos:(p.l4BeginPos+uint16(p.L4TCPPacket.tcpDataOffset)*4)]...)

	return &p, nil
}

// GetTCPData returns any additional data in the packet
func (p *Packet) GetTCPData() []byte {
	return p.L4TCPPacket.tcpData
}

// SetTCPData returns any additional data in the packet
func (p *Packet) SetTCPData(b []byte) {
	p.L4TCPPacket.tcpData = b
}

// GetTCPOptions returns any additional options in the packet
func (p *Packet) GetTCPOptions() []byte {
	return p.L4TCPPacket.tcpOptions
}

// DropDetachedDataBytes removes any bytes that have been detached and stored locally
func (p *Packet) DropDetachedDataBytes() {
	p.L4TCPPacket.tcpData = []byte{}
}

// DropDetachedBytes removes any bytes that have been detached and stored locally
func (p *Packet) DropDetachedBytes() {

	p.L4TCPPacket.tcpOptions = []byte{}
	p.L4TCPPacket.tcpData = []byte{}
}

// TCPDataStartBytes provides the tcp data start offset in bytes
func (p *Packet) TCPDataStartBytes() uint16 {
	return p.l4BeginPos + uint16(p.L4TCPPacket.tcpDataOffset)*4
}

// Print is a print helper function
func (p *Packet) Print(context uint64) {

	dbgContext := context | p.context
	logPkt := false
	detailed := false

	if (log.GetLevel() == log.DebugLevel || context == 0) || (dbgContext&PacketTypeApplication != 0 && dbgContext&debugContextApp != 0) || (dbgContext&PacketTypeNetwork != 0 && dbgContext&debugContextNet != 0) {
		logPkt = true
		detailed = true
	} else if dbgContext&debugContext != 0 {
		logPkt = true
	}

	var buf string
	print := false

	if logPkt || log.GetLevel() == log.DebugLevel {
		if printCount%200 == 0 {
			buf += fmt.Sprintf("Packet: %5s %5s %25s %15s %5s %15s %5s %6s %20s %20s %6s %20s %20s %2s %5s %5s\n",
				"IPID", "Dir", "Comment", "SIP", "SP", "DIP", "DP", "Flags", "TCPSeq", "TCPAck", "TCPLen", "ExpAck", "ExpSeq", "DO", "Acsum", "Ccsum")
		}
		printCount++
		offset := 0

		if (p.L4TCPPacket.TCPFlags & TCPSynMask) == TCPSynMask {
			offset = 1
		}

		expAck := p.L4TCPPacket.TCPSeq + uint32(p.IPTotalLength-p.TCPDataStartBytes()) + uint32(offset)
		ccsum := p.computeTCPChecksum()
		csumValidationStr := ""

		if p.L4TCPPacket.TCPChecksum != ccsum {
			csumValidationStr = "Bad Checksum"
		}

		buf += fmt.Sprintf("Packet: %5d %5s %25s %15s %5d %15s %5d %6s %20d %20d %6d %20d %20d %2d %5d %5d %12s\n",
			p.ipID,
			flagsToDir(p.context|context),
			flagsToStr(p.context|context),
			p.SourceAddress.To4().String(), p.L4TCPPacket.SourcePort,
			p.DestinationAddress.To4().String(), p.L4TCPPacket.DestinationPort,
			tcpFlagsToStr(p.L4TCPPacket.TCPFlags),
			p.L4TCPPacket.TCPSeq, p.L4TCPPacket.TCPAck, p.IPTotalLength-p.TCPDataStartBytes(),
			expAck, expAck, p.L4TCPPacket.tcpDataOffset,
			p.L4TCPPacket.TCPChecksum, ccsum, csumValidationStr)
		print = true
	}

	if detailed || log.GetLevel() == log.DebugLevel {
		pktBytes := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 8, 0}
		pktBytes = append(pktBytes, p.Buffer...)
		pktBytes = append(pktBytes, p.L4TCPPacket.tcpOptions...)
		pktBytes = append(pktBytes, p.L4TCPPacket.tcpData...)
		buf += fmt.Sprintf("%s\n", hex.Dump(pktBytes))
		print = true
	}

	if print {
		log.WithFields(log.Fields{
			"package": "packet",
		}).Info(buf)
	}
}

//GetBytes returns the bytes in the packet. It consolidates in case of changes as well
func (p *Packet) GetBytes() []byte {

	pktBytes := []byte{}
	pktBytes = append(pktBytes, p.Buffer...)
	pktBytes = append(pktBytes, p.L4TCPPacket.tcpOptions...)
	pktBytes = append(pktBytes, p.L4TCPPacket.tcpData...)
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

	if uint16(len(p.Buffer)) >= p.IPTotalLength {
		return p.Buffer[p.TCPDataStartBytes():p.IPTotalLength]
	}

	return []byte{}
}

// CheckTCPAuthenticationOption ensures authentication option exists at the offset provided
func (p *Packet) CheckTCPAuthenticationOption(iOptionLength int) (err error) {
	_, present := p.TCPOptionData(TCPFastopenCookie)
	if present {
		return nil
	}
	return fmt.Errorf("TCP Option Not Found")

}

// FixupIPHdrOnDataModify modifies the IP header fields and checksum
func (p *Packet) FixupIPHdrOnDataModify(old, new uint16) {

	// IP Header Processing
	// IP chekcsum fixup.
	p.ipChecksum = incCsum16(p.ipChecksum, old, new)
	// Update IP Total Length.
	p.IPTotalLength = p.IPTotalLength + new - old

	binary.BigEndian.PutUint16(p.Buffer[ipLengthPos:ipLengthPos+2], p.IPTotalLength)
	binary.BigEndian.PutUint16(p.Buffer[ipChecksumPos:ipChecksumPos+2], p.ipChecksum)
}

// FixTCPCsum fixes the checksum if seq/ack are increased
func (p *Packet) FixTCPCsum(old, new uint32) {

	a := uint32(-p.L4TCPPacket.TCPChecksum)
	a += uint32(uint32Delta(new, old))

	for (a >> 16) != 0 {
		a = (a & 0xffff) + (a >> 16)
	}

	p.L4TCPPacket.TCPChecksum = -uint16(a)
	binary.BigEndian.PutUint16(p.Buffer[TCPChecksumPos:TCPChecksumPos+2], p.L4TCPPacket.TCPChecksum)
}

// IncreaseTCPSeq increases TCP seq number by incr
func (p *Packet) IncreaseTCPSeq(incr uint32) {

	oldTCPSeq := p.L4TCPPacket.TCPSeq
	p.L4TCPPacket.TCPSeq = p.L4TCPPacket.TCPSeq + incr
	binary.BigEndian.PutUint32(p.Buffer[tcpSeqPos:tcpSeqPos+4], p.L4TCPPacket.TCPSeq)
	p.FixTCPCsum(oldTCPSeq, p.L4TCPPacket.TCPSeq)
}

// DecreaseTCPSeq decreases TCP seq number by decr
func (p *Packet) DecreaseTCPSeq(decr uint32) {

	oldTCPSeq := p.L4TCPPacket.TCPSeq
	p.L4TCPPacket.TCPSeq = p.L4TCPPacket.TCPSeq - decr
	binary.BigEndian.PutUint32(p.Buffer[tcpSeqPos:tcpSeqPos+4], p.L4TCPPacket.TCPSeq)
	p.FixTCPCsum(oldTCPSeq, p.L4TCPPacket.TCPSeq)
}

// IncreaseTCPAck increases TCP ack number by incr
func (p *Packet) IncreaseTCPAck(incr uint32) {

	oldTCPAck := p.L4TCPPacket.TCPAck
	p.L4TCPPacket.TCPAck = p.L4TCPPacket.TCPAck + incr
	binary.BigEndian.PutUint32(p.Buffer[tcpAckPos:tcpAckPos+4], p.L4TCPPacket.TCPAck)
	p.FixTCPCsum(oldTCPAck, p.L4TCPPacket.TCPAck)
}

// DecreaseTCPAck decreases TCP ack number by decr
func (p *Packet) DecreaseTCPAck(decr uint32) {

	oldTCPAck := p.L4TCPPacket.TCPAck
	p.L4TCPPacket.TCPAck = p.L4TCPPacket.TCPAck - decr
	binary.BigEndian.PutUint32(p.Buffer[tcpAckPos:tcpAckPos+4], p.L4TCPPacket.TCPAck)
	p.FixTCPCsum(oldTCPAck, p.L4TCPPacket.TCPAck)
}

// computeTCPChecksumDelta
func (p *Packet) computeTCPChecksumDelta(tcpOptions []byte, tcpOptionLen uint16, tcpData []byte, tcpDataLen uint16) (delta uint32) {

	delta = 0
	// Adjust with the payload checksum
	delta += uint32(checksumDelta(append(tcpOptions, tcpData...)))
	delta = delta&0xffff + (delta>>16)&0xffff
	// Adjust with the length modification
	delta += uint32(tcpDataLen + tcpOptionLen)
	delta = delta&0xffff + (delta>>16)&0xffff
	// Adjust for options removed
	delta += (uint32(tcpOptionLen/4) << 12)
	delta = delta&0xffff + (delta>>16)&0xffff
	for (delta >> 16) != 0 {
		delta = (delta & 0xffff) + (delta >> 16)
	}

	return
}

// FixupTCPHdrOnTCPDataDetach modifies the TCP header fields and checksum
func (p *Packet) FixupTCPHdrOnTCPDataDetach(dataLength uint16, optionLength uint16) {

	log.WithFields(log.Fields{
		"package":          "packet",
		"flags":            p.L4TCPPacket.TCPFlags,
		"len":              p.IPTotalLength - p.TCPDataStartBytes(),
		"bufLen":           len(p.Buffer),
		"dataLength":       dataLength,
		"tcpDataLength":    len(p.L4TCPPacket.tcpData),
		"optionLength":     optionLength,
		"tcpOptionsLength": len(p.L4TCPPacket.tcpOptions),
	}).Debug("Fixup TCP Hdr On TCP Data Detach")

	// Update TCP checksum
	a := uint32(-p.L4TCPPacket.TCPChecksum) - p.computeTCPChecksumDelta(p.L4TCPPacket.tcpOptions[:optionLength], optionLength, p.L4TCPPacket.tcpData[:dataLength], dataLength)
	a = a + (a >> 16)
	p.L4TCPPacket.TCPChecksum = -uint16(a)
	binary.BigEndian.PutUint16(p.Buffer[TCPChecksumPos:TCPChecksumPos+2], p.L4TCPPacket.TCPChecksum)

	// Update DataOffset
	p.L4TCPPacket.tcpDataOffset = p.L4TCPPacket.tcpDataOffset - uint8(optionLength/4)
	p.Buffer[tcpDataOffsetPos] = p.L4TCPPacket.tcpDataOffset << 4
}

// tcpDataDetach splits the p.Buffer into p.Buffer (header + some options), p.L4TCPPacket.tcpOptions (optionLength) and p.TCPData (dataLength)
func (p *Packet) tcpDataDetach(optionLength uint16, dataLength uint16) (err error) {

	// Setup buffer for Options, Data and reduce the original buffer
	if dataLength != 0 {
		if uint16(len(p.Buffer)) >= p.IPTotalLength {
			p.L4TCPPacket.tcpData = p.Buffer[p.TCPDataStartBytes():p.IPTotalLength]
		} else if (p.IPTotalLength - p.TCPDataStartBytes()) != uint16(len(p.L4TCPPacket.tcpData)) {
			log.WithFields(log.Fields{
				"package":      "packet",
				"error":        err.Error(),
				"optionLength": optionLength,
				"dataLength":   dataLength,
			}).Debug("Not handling concat of data buffers in tcpDataDetach")

			return fmt.Errorf("Not handling concat of data buffers")
		}
	}

	if optionLength != 0 {
		if uint16(len(p.Buffer)) >= p.TCPDataStartBytes() {
			p.L4TCPPacket.tcpOptions = p.Buffer[p.TCPDataStartBytes()-optionLength : p.TCPDataStartBytes()]
		} else if optionLength != uint16(len(p.L4TCPPacket.tcpOptions)) {
			log.WithFields(log.Fields{
				"package":      "packet",
				"error":        err.Error(),
				"optionLength": optionLength,
				"dataLength":   dataLength,
			}).Debug("Not handling concat of options buffers")

			return fmt.Errorf("Not handling concat of options buffers")
		}
	}

	if uint16(len(p.Buffer)) >= (p.TCPDataStartBytes() - optionLength) {
		p.Buffer = p.Buffer[:p.TCPDataStartBytes()-optionLength]
	}

	return
}

// TCPDataDetach performs the following:
//   - Removes all TCP data from Buffer to TCPData.
//   - Removes "optionLength" bytes of options from TCP header to tcpOptions
//   - Updates IP Hdr (lengths, checksums)
//   - Updates TCP header (checksums)
func (p *Packet) TCPDataDetach(optionLength uint16) (err error) {

	// Length
	dataLength := p.IPTotalLength - p.TCPDataStartBytes()

	// detach TCP data
	if err = p.tcpDataDetach(optionLength, dataLength); err != nil {
		log.WithFields(log.Fields{
			"package":      "packet",
			"error":        err.Error(),
			"optionLength": optionLength,
			"dataLength":   dataLength,
		}).Debug("TCP Data Detach failed")

		return err
	}

	// Process TCP Header fields and metadata
	p.FixupTCPHdrOnTCPDataDetach(dataLength, optionLength)

	// Process IP Header fields
	p.FixupIPHdrOnDataModify(p.IPTotalLength, p.IPTotalLength-(dataLength+optionLength))
	return
}

// FixupTCPHdrOnTCPDataAttach modifies the TCP header fields and checksum
func (p *Packet) FixupTCPHdrOnTCPDataAttach(tcpOptions []byte, tcpData []byte) {

	log.WithFields(log.Fields{
		"package":   "packet",
		"Flags":     p.L4TCPPacket.TCPFlags,
		"newLength": p.IPTotalLength - p.TCPDataStartBytes(),
	}).Debug("Fixup TCP Hdr On TCP Data Attach")

	numberOfOptions := len(tcpOptions) / 4

	// TCP checksum fixup. Start with old checksum
	delta := p.computeTCPChecksumDelta(tcpOptions, uint16(len(tcpOptions)), tcpData, uint16(len(tcpData)))
	a := uint32(-p.L4TCPPacket.TCPChecksum) + delta
	a = a + (a >> 16)
	p.L4TCPPacket.TCPChecksum = -uint16(a)

	p.L4TCPPacket.tcpDataOffset = p.L4TCPPacket.tcpDataOffset + uint8(numberOfOptions)
	binary.BigEndian.PutUint16(p.Buffer[TCPChecksumPos:TCPChecksumPos+2], p.L4TCPPacket.TCPChecksum)
	p.Buffer[tcpDataOffsetPos] = p.L4TCPPacket.tcpDataOffset << 4

}

// tcpDataAttach splits the p.Buffer into p.Buffer (header + some options), p.L4TCPPacket.tcpOptions (optionLength) and p.TCPData (dataLength)
func (p *Packet) tcpDataAttach(options []byte, data []byte) (err error) {

	optionLength := len(options)

	if p.TCPDataStartBytes() != p.IPTotalLength && optionLength != 0 {
		log.WithFields(log.Fields{
			"package":         "packet",
			"optionLength":    optionLength,
			"p.IPTotalLength": p.IPTotalLength,
		}).Debug("Cannot insert options with existing data")
		return fmt.Errorf("Cannot insert options with existing data")
	}

	p.L4TCPPacket.tcpOptions = append(p.L4TCPPacket.tcpOptions, options...)

	dataLength := len(data)

	if dataLength != 0 {
		p.L4TCPPacket.tcpData = append(p.L4TCPPacket.tcpData, data...)
	}

	return
}

// TCPDataAttach modifies the TCP and IP header fields and checksum
func (p *Packet) TCPDataAttach(tcpOptions []byte, tcpData []byte) (err error) {

	log.WithFields(log.Fields{
		"package": "packet",
	}).Debug("TCP data attach")

	if err = p.tcpDataAttach(tcpOptions, tcpData); err != nil {
		log.WithFields(log.Fields{
			"package": "packet",
			"error":   err.Error(),
		}).Debug("TCP Data Attach failed")

		return err
	}

	// We are increasing tcpOptions by 1 32-bit word. We are always adding
	// our option last.
	packetLenIncrease := uint16(len(tcpData) + len(tcpOptions))

	// IP Header Processing
	p.FixupIPHdrOnDataModify(p.IPTotalLength, p.IPTotalLength+packetLenIncrease)

	// TCP Header Processing
	p.FixupTCPHdrOnTCPDataAttach(tcpOptions, tcpData)

	return
}

// L4FlowHash caclulate a hash string based on the 4-tuple
func (p *Packet) L4FlowHash() string {
	return p.SourceAddress.String() + ":" + p.DestinationAddress.String() + ":" + strconv.Itoa(int(p.L4TCPPacket.SourcePort)) + ":" + strconv.Itoa(int(p.L4TCPPacket.DestinationPort))
}

// L4ReverseFlowHash caclulate a hash string based on the 4-tuple by reversing source and destination information
func (p *Packet) L4ReverseFlowHash() string {
	return p.DestinationAddress.String() + ":" + p.SourceAddress.String() + ":" + strconv.Itoa(int(p.L4TCPPacket.DestinationPort)) + ":" + strconv.Itoa(int(p.L4TCPPacket.SourcePort))
}

func (p *Packet) GetProcessingStage() uint64 {
	return p.context
}

// SynAckNetworkHash calculates a hash based on the destination IP and port
func (p *Packet) SynAckNetworkHash() string {
	return p.DestinationAddress.String() + ":" + strconv.Itoa(int(p.L4TCPPacket.DestinationPort))
}

// SynAckApplicationHash calculates a hash based on src/dest port and dest IP address
func (p *Packet) SynAckApplicationHash() string {
	return p.SourceAddress.String() + ":" + strconv.Itoa(int(p.L4TCPPacket.SourcePort)) + ":" + strconv.Itoa(int(p.L4TCPPacket.DestinationPort))
}
