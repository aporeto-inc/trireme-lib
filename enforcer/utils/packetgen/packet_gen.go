//Package packetgen "PacketGen" is a Packet Generator library
//Current version: V1.0, Updates are coming soon
package packetgen

//Go libraries
import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//NewPacket returns a packet strut which implements PacketManipulator
func NewPacket() PacketManipulator {

	return &Packet{}
}

//AddEthernetLayer creates an Ethernet layer
func (p *Packet) AddEthernetLayer(srcMACstr string, dstMACstr string) error {

	if p.EthernetLayer != nil {
		return fmt.Errorf("Ethernet Layer already exists")
	}

	var srcMAC, dstMAC net.HardwareAddr

	//MAC address of the source
	srcMAC, _ = net.ParseMAC(srcMACstr)

	if srcMAC == nil {
		return fmt.Errorf("No source MAC given")
	}

	//MAC address of the destination
	dstMAC, _ = net.ParseMAC(dstMACstr)

	if dstMAC == nil {
		return fmt.Errorf("No destination MAC given")
	}

	//Ethernet packet header
	p.EthernetLayer = &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	return nil
}

//GetEthernetPacket returns the ethernet layer created
func (p *Packet) GetEthernetPacket() layers.Ethernet {

	return *p.EthernetLayer
}

//AddIPLayer creates an IP layer
func (p *Packet) AddIPLayer(srcIPstr string, dstIPstr string) error {

	if p.IPLayer != nil {
		return fmt.Errorf("IP Layer already exists")
	}

	var srcIP, dstIP net.IP

	//IP address of the source
	srcIP = net.ParseIP(srcIPstr)

	if srcIP == nil {
		return fmt.Errorf("No source IP given")
	}

	//IP address of the destination
	dstIP = net.ParseIP(dstIPstr)

	if dstIP == nil {
		return fmt.Errorf("No destination IP given")
	}

	//IP packet header
	p.IPLayer = &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	return nil
}

//GetIPChecksum returns IP cheksum
func (p *Packet) GetIPChecksum() uint16 {

	return p.IPLayer.Checksum
}

//GetIPPacket returns IP checksum
func (p *Packet) GetIPPacket() layers.IPv4 {

	return *p.IPLayer
}

//AddTCPLayer creates a TCP layer
func (p *Packet) AddTCPLayer(srcPort layers.TCPPort, dstPort layers.TCPPort) error {

	if p.TCPLayer != nil {
		return fmt.Errorf("TCP Layer already exists")
	}

	if srcPort == 0 {
		return fmt.Errorf("No source TCP port given")
	}

	if dstPort == 0 {
		return fmt.Errorf("No destination TCP port given")
	}

	//TCP packet header
	p.TCPLayer = &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Window:  1505,
		Urgent:  0,
		Seq:     11050,
		Ack:     0,
		ACK:     false,
		SYN:     false,
		FIN:     false,
		RST:     false,
		URG:     false,
		ECE:     false,
		CWR:     false,
		NS:      false,
		PSH:     false,
	}

	p.TCPLayer.SetNetworkLayerForChecksum(p.IPLayer)

	return nil
}

//GetTCPPacket returns created TCP packet
func (p *Packet) GetTCPPacket() layers.TCP {

	return *p.TCPLayer
}

//GetTCPSequenceNumber returns TCP Sequence number
func (p *Packet) GetTCPSequenceNumber() uint32 {

	return p.TCPLayer.Seq
}

//GetTCPAcknowledgementNumber returns TCP Acknowledgement number
func (p *Packet) GetTCPAcknowledgementNumber() uint32 {

	return p.TCPLayer.Ack
}

//GetTCPWindow returns TCP Window
func (p *Packet) GetTCPWindow() uint16 {

	return p.TCPLayer.Window
}

//GetTCPSyn returns TCP SYN flag
func (p *Packet) GetTCPSyn() bool {

	return p.TCPLayer.SYN
}

//GetTCPAck returns TCP ACK flag
func (p *Packet) GetTCPAck() bool {

	return p.TCPLayer.ACK
}

//GetTCPFin returns TCP FIN flag
func (p *Packet) GetTCPFin() bool {

	return p.TCPLayer.FIN
}

//GetTCPChecksum returns TCP checksum
func (p *Packet) GetTCPChecksum() uint16 {

	return p.TCPLayer.Checksum
}

//SetTCPSequenceNumber changes TCP sequence number
func (p *Packet) SetTCPSequenceNumber(seqNum uint32) error {

	if p.TCPLayer.Seq != 0 {
		return fmt.Errorf("Sequence number already exists")
	}

	p.TCPLayer.Seq = seqNum

	return nil
}

//SetTCPAcknowledgementNumber changes TCP Acknowledgement number
func (p *Packet) SetTCPAcknowledgementNumber(ackNum uint32) error {

	if p.TCPLayer.Ack != 0 {
		return fmt.Errorf("Acknowledgement number already exists")
	}

	p.TCPLayer.Ack = ackNum

	return nil
}

//SetTCPWindow changes the TCP window
func (p *Packet) SetTCPWindow(window uint16) error {

	if p.TCPLayer.Window != 0 {
		return fmt.Errorf("Window already exists")
	}

	p.TCPLayer.Window = window

	return nil
}

//SetTCPSyn changes the TCP SYN flag to true
func (p *Packet) SetTCPSyn() {

	p.TCPLayer.SYN = true
	p.TCPLayer.ACK = false
	p.TCPLayer.FIN = false
}

//SetTCPSynAck changes the TCP SYN and ACK flag to true
func (p *Packet) SetTCPSynAck() {

	p.TCPLayer.SYN = true
	p.TCPLayer.ACK = true
	p.TCPLayer.FIN = false
}

//SetTCPAck changes the TCP ACK flag to true
func (p *Packet) SetTCPAck() {

	p.TCPLayer.SYN = false
	p.TCPLayer.ACK = true
	p.TCPLayer.FIN = false
}

//NewTCPPayload adds new payload to TCP layer
func (p *Packet) NewTCPPayload(newPayload string) error {

	if p.TCPLayer.Payload != nil {
		return fmt.Errorf("Payload already exists")
	}

	p.TCPLayer.Payload = []byte(newPayload)

	return nil
}

//ToBytes creates a packet buffer and converts it into a complete packet with ethernet, IP and TCP (with options)
func (p *Packet) ToBytes() []byte {

	opts := gopacket.SerializeOptions{
		FixLengths:       true, //fix lengths based on the payload (data)
		ComputeChecksums: true, //compute checksum based on the payload during serialization
	}

	p.TCPLayer.SetNetworkLayerForChecksum(p.IPLayer)

	//Creating a packet buffer by serializing the ethernet, IP and TCP layers/packets
	packetBuf := gopacket.NewSerializeBuffer()
	tcpPayload := gopacket.Payload(p.TCPLayer.Payload)
	gopacket.SerializeLayers(packetBuf, opts, p.EthernetLayer, p.IPLayer, p.TCPLayer, tcpPayload)
	//Converting into bytes and removing the ethernet from the layers
	bytes := packetBuf.Bytes()
	bytesWithoutEthernet := bytes[14:]

	var finalBytes []byte
	finalBytes = append(finalBytes, bytesWithoutEthernet...)

	return finalBytes
}

//NewTCPPacketFlow returns PacketFlow struct which implements PacketFlowManipulator
func NewTCPPacketFlow(smac string, dmac string, sip string, dip string, sport layers.TCPPort, dport layers.TCPPort) PacketFlowManipulator {

	initialTupules := &PacketFlow{
		sMAC:  smac,
		dMAC:  dmac,
		sIP:   sip,
		dIP:   dip,
		sPort: sport,
		dPort: dport,
		Flow:  make([]PacketManipulator, 0),
	}

	return initialTupules
}

//GenerateTCPFlow returns an array of PacketFlowManipulator interface
func (p *PacketFlow) GenerateTCPFlow(pt PacketFlowType) PacketFlowManipulator {

	if pt == 0 {
		//Create a SYN packet to initialize the flow
		firstPacket := NewPacket()
		firstPacket.AddEthernetLayer(p.sMAC, p.dMAC)
		firstPacket.AddIPLayer(p.sIP, p.dIP)
		firstPacket.AddTCPLayer(p.sPort, p.dPort)
		firstPacket.SetTCPSyn()
		firstPacket.SetTCPSequenceNumber(0)
		firstPacket.SetTCPAcknowledgementNumber(0)
		synPacket, _ := firstPacket.(*Packet)

		p.Flow = append(p.Flow, synPacket)

		//Create a SynAck packet
		secondPacket := NewPacket()
		secondPacket.AddEthernetLayer(p.sMAC, p.dMAC)
		secondPacket.AddIPLayer(p.dIP, p.sIP)
		secondPacket.AddTCPLayer(p.dPort, p.sPort)
		secondPacket.SetTCPSynAck()
		secondPacket.SetTCPSequenceNumber(0)
		secondPacket.SetTCPAcknowledgementNumber(synPacket.TCPLayer.Seq + 1)
		synackPacket, _ := secondPacket.(*Packet)

		p.Flow = append(p.Flow, synackPacket)

		//Create an Ack Packet
		thirdPacket := NewPacket()
		thirdPacket.AddEthernetLayer(p.sMAC, p.dMAC)
		thirdPacket.AddIPLayer(p.sIP, p.dIP)
		thirdPacket.AddTCPLayer(p.sPort, p.dPort)
		thirdPacket.SetTCPAck()
		thirdPacket.SetTCPSequenceNumber(synackPacket.TCPLayer.Ack)
		thirdPacket.SetTCPAcknowledgementNumber(synackPacket.TCPLayer.Seq + 1)
		ackPacket, _ := thirdPacket.(*Packet)

		p.Flow = append(p.Flow, ackPacket)
	}

	return p
}

//GenerateTCPFlowPayload Coming soon...
func (p *PacketFlow) GenerateTCPFlowPayload(newPayload string) PacketFlowManipulator {

	return nil
}

//AppendPacket adds the packet to Flow field of PacketFlowManipulator interface
func (p *PacketFlow) AppendPacket(pm PacketManipulator) int {

	p.Flow = append(p.Flow, pm)

	return p.GetNumPackets()
}

//GetMatchPackets implicitly returns the matching packets requested by the user
func (p *PacketFlow) getMatchPackets(syn, ack, fin bool) PacketFlowManipulator {

	packetsInFlow := NewTCPPacketFlow(p.sMAC, p.dMAC, p.sIP, p.dIP, p.sPort, p.dPort)

	for j := 0; j < len(p.Flow); j++ {
		if p.Flow[j].GetTCPSyn() == syn && p.Flow[j].GetTCPAck() == ack && p.Flow[j].GetTCPFin() == fin {
			packetsInFlow.AppendPacket(p.Flow[j])
		}
	}

	return packetsInFlow
}

//GetFirstSynPacket return first Syn packet from the flow
func (p *PacketFlow) GetFirstSynPacket() PacketManipulator {

	return p.GetSynPackets().GetNthPacket(0)
}

//GetFirstSynAckPacket return first SynAck packet from the flow
func (p *PacketFlow) GetFirstSynAckPacket() PacketManipulator {

	return p.GetSynAckPackets().GetNthPacket(0)
}

//GetFirstAckPacket return first Ack packet from the flow
func (p *PacketFlow) GetFirstAckPacket() PacketManipulator {

	return p.GetAckPackets().GetNthPacket(0)
}

//GetSynPackets returns the SYN packets
func (p *PacketFlow) GetSynPackets() PacketFlowManipulator {

	return p.getMatchPackets(true, false, false)
}

//GetSynAckPackets returns the SynAck packets
func (p *PacketFlow) GetSynAckPackets() PacketFlowManipulator {

	return p.getMatchPackets(true, true, false)
}

//GetAckPackets returns the Ack Packets
func (p *PacketFlow) GetAckPackets() PacketFlowManipulator {

	return p.getMatchPackets(false, true, false)
}

//GetNthPacket returns the packet requested by the user from the array
func (p *PacketFlow) GetNthPacket(index int) PacketManipulator {

	for i := 0; i < len(p.Flow); i++ {
		if index == i {
			return p.Flow[i]
		}
	}

	panic("Index out of range")
}

//GetNumPackets returns an array of packets
func (p *PacketFlow) GetNumPackets() int {

	return len(p.Flow)
}
