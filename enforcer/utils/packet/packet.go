// Package packet support for TCP/IP packet manipulations
// needed by the Aporeto infrastructure.
package packet

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/golang/glog"
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
	f, _ := os.Create("/tmp/packet")
	defer f.Close()
	w := bufio.NewWriter(f)
	debugContext = 0
	debugContextApp = 0 //PacketStageIncoming
	debugContextNet = 0 //PacketStageOutgoing
	w.WriteString("Declared Globals")
	w.Flush()
	cbuf := fmt.Sprintf(" Network:0x%04x Application:0x%04x",
		PacketTypeNetwork,
		PacketTypeApplication)
	w.WriteString("CBUF done")
	w.Flush()
	fbuf := fmt.Sprintf(" Incoming:0x%04x Auth:0x%04x Service:0x%04x Outgoing:0x%04x",
		PacketStageIncoming,
		PacketStageAuth,
		PacketStageService,
		PacketStageOutgoing)
	w.WriteString("fbuf done")
	w.Flush()
	flag.Uint64Var(&debugContext, "debug-packet-context", 0, "packet contexts to debug -"+cbuf+fbuf)
	w.WriteString("DebugContext done")
	w.Flush()
	flag.Uint64Var(&debugContextApp, "debug-packet-context-app", 0, "app packet contexts to debug -"+fbuf)
	w.WriteString("DebugContextApp done")
	w.Flush()
	flag.Uint64Var(&debugContextNet, "debug-packet-context-net", 0, "net packet contexts to debug -"+fbuf)
	w.WriteString("DebugContextNet done")
	w.Flush()
}

// New returns a pointer to Packet structure built from the
// provided bytes buffer which is expected to contain valid TCP/IP
// packet bytes.
func New(context uint64, bytes []byte) (packet *Packet, err error) {

	var p Packet

	// Buffer Setup
	p.Buffer = bytes

	// Options and Payload that maybe added
	p.tcpOptions = []byte{}
	p.tcpData = []byte{}

	// IP Header Processing
	p.ipHeaderLen = bytes[ipHdrLenPos] & ipHdrLenMask
	p.IPTotalLength = binary.BigEndian.Uint16(bytes[ipLengthPos : ipLengthPos+2])
	p.ipID = binary.BigEndian.Uint16(bytes[ipIDPos : ipIDPos+2])
	p.ipChecksum = binary.BigEndian.Uint16(bytes[ipChecksumPos : ipChecksumPos+2])
	p.SourceAddress = net.IP(bytes[ipSourceAddrPos : ipSourceAddrPos+4])
	p.DestinationAddress = net.IP(bytes[ipDestAddrPos : ipDestAddrPos+4])

	// Some sanity checking...
	if p.IPTotalLength < minIPPacketLen {
		return nil, fmt.Errorf("IP Packet too small")
	}
	if p.ipHeaderLen != minIPHdrWords {
		return nil, fmt.Errorf("Packets with IP options not supported (hdrlen=%d)", p.ipHeaderLen)
	}
	if p.IPTotalLength != uint16(len(p.Buffer)) {
		if p.IPTotalLength < uint16(len(p.Buffer)) {
			p.Buffer = p.Buffer[:p.IPTotalLength]
		} else {
			return nil, fmt.Errorf("Stated IP packet length (%d) differs from bytes available (%d)", p.IPTotalLength, len(p.Buffer))
		}
	}

	// TCP Header Processing
	p.tcpBeginPos = minIPHdrSize
	p.TCPChecksum = binary.BigEndian.Uint16(bytes[TCPChecksumPos : TCPChecksumPos+2])
	p.SourcePort = binary.BigEndian.Uint16(bytes[tcpSourcePortPos : tcpSourcePortPos+2])
	p.DestinationPort = binary.BigEndian.Uint16(bytes[tcpDestPortPos : tcpDestPortPos+2])
	p.TCPAck = binary.BigEndian.Uint32(bytes[tcpAckPos : tcpAckPos+4])
	p.TCPSeq = binary.BigEndian.Uint32(bytes[tcpSeqPos : tcpSeqPos+4])
	p.tcpDataOffset = (bytes[tcpDataOffsetPos] & tcpDataOffsetMask) >> 4
	p.TCPFlags = bytes[tcpFlagsOffsetPos]

	p.context = context

	return &p, nil
}

// GetTCPData returns any additional data in the packet
func (p *Packet) GetTCPData() []byte {

	return p.tcpData
}

// SetTCPData returns any additional data in the packet
func (p *Packet) SetTCPData(b []byte) {

	p.tcpData = b
}

// GetTCPOptions returns any additional options in the packet
func (p *Packet) GetTCPOptions() []byte {

	return p.tcpOptions
}

// DropDetachedDataBytes removes any bytes that have been detached and stored locally
func (p *Packet) DropDetachedDataBytes() {

	p.tcpData = []byte{}
}

// DropDetachedBytes removes any bytes that have been detached and stored locally
func (p *Packet) DropDetachedBytes() {

	p.tcpOptions = []byte{}
	p.tcpData = []byte{}
}

// TCPDataStartBytes provides the tcp data start offset in bytes
func (p *Packet) TCPDataStartBytes() uint16 {

	return p.tcpBeginPos + uint16(p.tcpDataOffset)*4
}

// Print is a print helper function
func (p *Packet) Print(context uint64) {

	dbgContext := context | p.context
	logPkt := false
	detailed := false

	if !flag.Parsed() {
		os.Stderr.Write([]byte("ERROR: packet logging before flag.Parse: "))
	}

	if glog.V(10) || context == 0 {
		logPkt = true
		detailed = true
	} else if dbgContext&debugContext != 0 {
		logPkt = true
	} else if dbgContext&PacketTypeApplication != 0 && dbgContext&debugContextApp != 0 {
		logPkt = true
		detailed = true
	} else if dbgContext&PacketTypeNetwork != 0 && dbgContext&debugContextNet != 0 {
		logPkt = true
		detailed = true
	}

	var buf string
	print := false
	if logPkt || glog.V(8) == glog.Verbose(true) {
		if printCount%200 == 0 {
			buf += fmt.Sprintf("Packet: %5s %5s %25s %15s %5s %15s %5s %6s %20s %20s %6s %20s %20s %2s %5s %5s\n",
				"IPID", "Dir", "Comment", "SIP", "SP", "DIP", "DP", "Flags", "TCPSeq", "TCPAck", "TCPLen", "ExpAck", "ExpSeq", "DO", "Acsum", "Ccsum")
		}
		printCount++
		offset := 0
		if (p.TCPFlags & TCPSynMask) == TCPSynMask {
			offset = 1
		}
		expAck := p.TCPSeq + uint32(p.IPTotalLength-p.TCPDataStartBytes()) + uint32(offset)
		ccsum := p.computeTCPChecksum()
		csumValidationStr := ""
		if p.TCPChecksum != ccsum {
			csumValidationStr = "Bad Checksum"
		}
		buf += fmt.Sprintf("Packet: %5d %5s %25s %15s %5d %15s %5d %6s %20d %20d %6d %20d %20d %2d %5d %5d %12s\n",
			p.ipID,
			flagsToDir(p.context|context),
			flagsToStr(p.context|context),
			p.SourceAddress.To4().String(), p.SourcePort,
			p.DestinationAddress.To4().String(), p.DestinationPort,
			tcpFlagsToStr(p.TCPFlags),
			p.TCPSeq, p.TCPAck, p.IPTotalLength-p.TCPDataStartBytes(),
			expAck, expAck, p.tcpDataOffset,
			p.TCPChecksum, ccsum, csumValidationStr)
		print = true
	}

	if detailed || glog.V(9) == glog.Verbose(true) {
		pktBytes := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 8, 0}
		pktBytes = append(pktBytes, p.Buffer...)
		pktBytes = append(pktBytes, p.tcpOptions...)
		pktBytes = append(pktBytes, p.tcpData...)
		buf += fmt.Sprintf("%s\n", hex.Dump(pktBytes))
		print = true
	}

	if print {
		fmt.Print(buf)
	}
}

//GetBytes returns the bytes in the packet. It consolidates in case of changes as well
func (p *Packet) GetBytes() []byte {

	pktBytes := []byte{}
	pktBytes = append(pktBytes, p.Buffer...)
	pktBytes = append(pktBytes, p.tcpOptions...)
	pktBytes = append(pktBytes, p.tcpData...)
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

	optionLength := uint16(iOptionLength)

	// Our option was not found in the right place. We don't do anything
	// for this packet.
	if p.Buffer[p.TCPDataStartBytes()-optionLength] != TCPAuthenticationOption {
		err = fmt.Errorf("TCP option not found")
		return
	}
	return
}

// fixupIPHdrOnTCPDataModify modifies the IP header fields and checksum
func (p *Packet) fixupIPHdrOnTCPDataModify(packetLenIncrease uint16) {

	// IP Header Processing
	// IP chekcsum fixup.
	p.ipChecksum = -(-p.ipChecksum + packetLenIncrease)
	// Update IP Total Length.
	p.IPTotalLength = p.IPTotalLength + packetLenIncrease

	binary.BigEndian.PutUint16(p.Buffer[ipLengthPos:ipLengthPos+2], p.IPTotalLength)
	binary.BigEndian.PutUint16(p.Buffer[ipChecksumPos:ipChecksumPos+2], p.ipChecksum)
}

// FixTCPCsum fixes the checksum if seq/ack are increased
func (p *Packet) FixTCPCsum(old, new uint32) {

	a := uint32(-p.TCPChecksum)
	a += uint32(uint32Delta(new, old))
	for (a >> 16) != 0 {
		a = (a & 0xffff) + (a >> 16)
	}
	p.TCPChecksum = -uint16(a)
	binary.BigEndian.PutUint16(p.Buffer[TCPChecksumPos:TCPChecksumPos+2], p.TCPChecksum)
}

// IncreaseTCPSeq increases TCP seq number by incr
func (p *Packet) IncreaseTCPSeq(incr uint32) {

	oldTCPSeq := p.TCPSeq
	p.TCPSeq = p.TCPSeq + incr
	binary.BigEndian.PutUint32(p.Buffer[tcpSeqPos:tcpSeqPos+4], p.TCPSeq)
	p.FixTCPCsum(oldTCPSeq, p.TCPSeq)
}

// DecreaseTCPSeq decreases TCP seq number by decr
func (p *Packet) DecreaseTCPSeq(decr uint32) {

	oldTCPSeq := p.TCPSeq
	p.TCPSeq = p.TCPSeq - decr
	binary.BigEndian.PutUint32(p.Buffer[tcpSeqPos:tcpSeqPos+4], p.TCPSeq)
	p.FixTCPCsum(oldTCPSeq, p.TCPSeq)
}

// IncreaseTCPAck increases TCP ack number by incr
func (p *Packet) IncreaseTCPAck(incr uint32) {

	oldTCPAck := p.TCPAck
	p.TCPAck = p.TCPAck + incr
	binary.BigEndian.PutUint32(p.Buffer[tcpAckPos:tcpAckPos+4], p.TCPAck)
	p.FixTCPCsum(oldTCPAck, p.TCPAck)
}

// DecreaseTCPAck decreases TCP ack number by decr
func (p *Packet) DecreaseTCPAck(decr uint32) {

	oldTCPAck := p.TCPAck
	p.TCPAck = p.TCPAck - decr
	binary.BigEndian.PutUint32(p.Buffer[tcpAckPos:tcpAckPos+4], p.TCPAck)
	p.FixTCPCsum(oldTCPAck, p.TCPAck)
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

// FixupIPHdrOnTCPDataDetach modifies the IP header fields and checksum
func (p *Packet) FixupIPHdrOnTCPDataDetach(packetLenDecrease uint16) {

	p.fixupIPHdrOnTCPDataModify(-(packetLenDecrease))
}

// FixupTCPHdrOnTCPDataDetach modifies the TCP header fields and checksum
func (p *Packet) FixupTCPHdrOnTCPDataDetach(dataLength uint16, optionLength uint16) {

	glog.V(4).Infof("FixupTCPHdrOnTCPDataDetach: Flags=%02x Len=%d BufLen=%d dl=%d/%d ol=%d/%d",
		p.TCPFlags,
		p.IPTotalLength-p.TCPDataStartBytes(),
		len(p.Buffer),
		dataLength, len(p.tcpData),
		optionLength, len(p.tcpOptions))

	// Update TCP checksum
	a := uint32(-p.TCPChecksum) - p.computeTCPChecksumDelta(p.tcpOptions[:optionLength], optionLength, p.tcpData[:dataLength], dataLength)
	a = a + (a >> 16)
	p.TCPChecksum = -uint16(a)
	binary.BigEndian.PutUint16(p.Buffer[TCPChecksumPos:TCPChecksumPos+2], p.TCPChecksum)

	// Update DataOffset
	p.tcpDataOffset = p.tcpDataOffset - uint8(optionLength/4)
	p.Buffer[tcpDataOffsetPos] = p.tcpDataOffset << 4
}

// tcpDataDetach splits the p.Buffer into p.Buffer (header + some options), p.tcpOptions (optionLength) and p.TCPData (dataLength)
func (p *Packet) tcpDataDetach(optionLength uint16, dataLength uint16) (err error) {

	// Setup buffer for Options, Data and reduce the original buffer
	if dataLength != 0 {
		if uint16(len(p.Buffer)) >= p.IPTotalLength {
			p.tcpData = p.Buffer[p.TCPDataStartBytes():p.IPTotalLength]
		} else if (p.IPTotalLength - p.TCPDataStartBytes()) != uint16(len(p.tcpData)) {
			return fmt.Errorf("Not handling concat of data buffers")
		}
	}
	if optionLength != 0 {
		if uint16(len(p.Buffer)) >= p.TCPDataStartBytes() {
			p.tcpOptions = p.Buffer[p.TCPDataStartBytes()-optionLength : p.TCPDataStartBytes()]
		} else if optionLength != uint16(len(p.tcpOptions)) {
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
		return err
	}

	// Process TCP Header fields and metadata
	p.FixupTCPHdrOnTCPDataDetach(dataLength, optionLength)

	// Process IP Header fields
	p.FixupIPHdrOnTCPDataDetach(dataLength + optionLength)

	return
}

// FixupIPHdrOnTCPDataAttach modifies the IP header fields and checksum
func (p *Packet) FixupIPHdrOnTCPDataAttach(packetLenIncrease uint16) {

	p.fixupIPHdrOnTCPDataModify(packetLenIncrease)
}

// FixupTCPHdrOnTCPDataAttach modifies the TCP header fields and checksum
func (p *Packet) FixupTCPHdrOnTCPDataAttach(tcpOptions []byte, tcpData []byte) {

	glog.V(4).Infof("FixupTCPHdrOnTCPDataAttach: Flags=%02x NewLen=%d\n", p.TCPFlags,
		p.IPTotalLength-p.TCPDataStartBytes())

	numberOfOptions := len(tcpOptions) / 4
	// TCP checksum fixup. Start with old checksum
	delta := p.computeTCPChecksumDelta(tcpOptions, uint16(len(tcpOptions)), tcpData, uint16(len(tcpData)))
	a := uint32(-p.TCPChecksum) + delta
	a = a + (a >> 16)
	p.TCPChecksum = -uint16(a)

	// Modify the fields
	p.tcpDataOffset = p.tcpDataOffset + uint8(numberOfOptions)
	binary.BigEndian.PutUint16(p.Buffer[TCPChecksumPos:TCPChecksumPos+2], p.TCPChecksum)
	p.Buffer[tcpDataOffsetPos] = p.tcpDataOffset << 4
}

// tcpDataAttach splits the p.Buffer into p.Buffer (header + some options), p.tcpOptions (optionLength) and p.TCPData (dataLength)
func (p *Packet) tcpDataAttach(options []byte, data []byte) (err error) {

	optionLength := len(options)
	if p.TCPDataStartBytes() != p.IPTotalLength && optionLength != 0 {
		return fmt.Errorf("Cannot insert options with existing data")
	}
	p.tcpOptions = append(p.tcpOptions, options...)

	dataLength := len(data)
	if dataLength != 0 {
		p.tcpData = append(p.tcpData, data...)
	}
	return
}

// TCPDataAttach modifies the TCP and IP header fields and checksum
func (p *Packet) TCPDataAttach(tcpOptions []byte, tcpData []byte) (err error) {

	if err = p.tcpDataAttach(tcpOptions, tcpData); err != nil {
		return err
	}

	// We are increasing tcpOptions by 1 32-bit word. We are always adding
	// our option last.
	packetLenIncrease := uint16(len(tcpData) + len(tcpOptions))

	// IP Header Processing
	p.FixupIPHdrOnTCPDataAttach(packetLenIncrease)

	// TCP Header Processing
	p.FixupTCPHdrOnTCPDataAttach(tcpOptions, tcpData)

	return
}

// L4FlowHash caclulate a hash string based on the 4-tuple
func (p *Packet) L4FlowHash() string {

	return p.SourceAddress.String() + ":" + p.DestinationAddress.String() + ":" + strconv.Itoa(int(p.SourcePort)) + ":" + strconv.Itoa(int(p.DestinationPort))
}

// L4ReverseFlowHash caclulate a hash string based on the 4-tuple by reversing source and destination information
func (p *Packet) L4ReverseFlowHash() string {

	return p.DestinationAddress.String() + ":" + p.SourceAddress.String() + ":" + strconv.Itoa(int(p.DestinationPort)) + ":" + strconv.Itoa(int(p.SourcePort))
}
