//Package packetgen is a Packet Generator library
//This is a beta version which returns only TCP 3-way handshake
//Updates are coming soon
package packetgen

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

//AddIPLayer creates an IP packet
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

//AddTCPLayer creates a TCP packet
func (p *Packet) AddTCPLayer(srcPort layers.TCPPort, dstPort layers.TCPPort) error {

	if p.TCPLayer != nil {
		return fmt.Errorf("TCP Layer already exists")
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

//NewTCPPayload adds new payload to TCP layer
func (p *Packet) NewTCPPayload(newPayload string) error {

	if p.TCPLayer.Payload != nil {
		return fmt.Errorf("Payload already exists")
	}

	p.TCPLayer.Payload = []byte(newPayload)

	return nil

}

//GetTCPChecksum returns TCP checksum
func (p *Packet) GetTCPChecksum() uint16 {

	return p.TCPLayer.Checksum

}

//GetIPPacket returns IP checksum
func (p *Packet) GetIPPacket() layers.IPv4 {

	return *p.IPLayer

}

//GetTCPPacket returns created TCP packet
func (p *Packet) GetTCPPacket() layers.TCP {

	return *p.TCPLayer

}

//ToBytes creates a packet buffer and converts it into a complete packet with ethernet, IP and TCP (with options)
func (p *Packet) ToBytes() [][]byte {

	//Creating a ethernet packet with fixed MAC addresses
	ethernetLayer := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
		EthernetType: layers.EthernetTypeIPv4,
	}

	//Options can be set
	opts := gopacket.SerializeOptions{
		FixLengths:       true, //fix lengths based on the payload (data)
		ComputeChecksums: true, //compute checksum based on the payload during serialization
	}

	p.TCPLayer.SetNetworkLayerForChecksum(p.IPLayer)

	//Creating a packet buffer by serializing the ethernet, IP and TCP layers/packets
	packetBuf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(packetBuf, opts, &ethernetLayer, p.IPLayer, p.TCPLayer)

	//Converting into bytes and removing the ethernet from the layers
	bytes := packetBuf.Bytes()
	bytesWithoutEthernet := bytes[:]

	var finalBytes [][]byte
	finalBytes = append(finalBytes, bytesWithoutEthernet)

	return finalBytes

}

//NewTCPPacketFlow returns PacketFlow struct which implements PacketFlowManipulator
func NewTCPPacketFlow(sip string, dip string, sport layers.TCPPort, dport layers.TCPPort) PacketFlowManipulator {

	initialTuplules := &PacketFlow{
		SIP:   sip,
		DIP:   dip,
		SPort: sport,
		DPort: dport,
		Flow:  make([]PacketManipulator, 0),
	}

	return initialTuplules

}

//GenerateTCPFlow returns an array of PacketFlowManipulator interface
func (p *PacketFlow) GenerateTCPFlow(bytePacket [][]byte) PacketFlowManipulator {

	//Create a SYN packet to initialize the flow
	firstPacket := NewPacket()
	firstPacket.AddIPLayer(p.SIP, p.DIP)
	firstPacket.AddTCPLayer(p.SPort, p.DPort)
	firstPacket.SetTCPSyn()
	firstPacket.SetTCPSequenceNumber(0)
	firstPacket.SetTCPAcknowledgementNumber(0)
	synPacket, _ := firstPacket.(*Packet)

	p.Flow = append(p.Flow, synPacket)

	//Create a SynAck packet
	secondPacket := NewPacket()
	secondPacket.AddIPLayer(p.DIP, p.SIP)
	secondPacket.AddTCPLayer(p.DPort, p.SPort)
	secondPacket.SetTCPSynAck()
	secondPacket.SetTCPSequenceNumber(0)
	secondPacket.SetTCPAcknowledgementNumber(synPacket.TCPLayer.Seq + 1)
	synackPacket, _ := secondPacket.(*Packet)

	p.Flow = append(p.Flow, synackPacket)

	//Create an Ack Packet
	thirdPacket := NewPacket()
	thirdPacket.AddIPLayer(p.SIP, p.DIP)
	thirdPacket.AddTCPLayer(p.SPort, p.DPort)
	thirdPacket.SetTCPAck()
	thirdPacket.SetTCPSequenceNumber(synackPacket.TCPLayer.Ack)
	thirdPacket.SetTCPAcknowledgementNumber(synackPacket.TCPLayer.Seq + 1)
	ackPacket, _ := thirdPacket.(*Packet)

	p.Flow = append(p.Flow, ackPacket)

	return p

}

//GenerateTCPFlowPayload Coming soon...
func (p *PacketFlow) GenerateTCPFlowPayload(newPayload string) PacketFlowManipulator {

	return nil

}

//AddPacket adds the packet to Flow field of PacketFlowManipulator interface
func (p *PacketFlow) AddPacket(pm PacketManipulator) {

	p.Flow = append(p.Flow, pm)

}

//GetMatchPackets implicitly returns the matching packets requested by the user
func (p *PacketFlow) GetMatchPackets(syn, ack, fin bool) PacketFlowManipulator {

	packetsInFlow := NewTCPPacketFlow(p.SIP, p.DIP, p.SPort, p.DPort)

	for j := 0; j < len(p.Flow); j++ {

		if p.Flow[j].GetTCPSyn() == syn && p.Flow[j].GetTCPAck() == ack && p.Flow[j].GetTCPFin() == fin {
			packetsInFlow.AddPacket(p.Flow[j])
		}

	}

	return packetsInFlow

}

//GetSynPackets returns the SYN packets
func (p *PacketFlow) GetSynPackets() PacketFlowManipulator {

	return p.GetMatchPackets(true, false, false)

}

//GetSynAckPackets returns the SynAck packets
func (p *PacketFlow) GetSynAckPackets() PacketFlowManipulator {

	return p.GetMatchPackets(true, true, false)

}

//GetAckPackets returns the Ack Packets
func (p *PacketFlow) GetAckPackets() PacketFlowManipulator {

	return p.GetMatchPackets(false, true, false)

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
