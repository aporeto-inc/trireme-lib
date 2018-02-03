//Package packetgen "PacketGen" is a Packet Generator library
//Current version: V1.0, Updates are coming soon
package packetgen

//Go libraries
import (
	"errors"
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

	if p.ethernetLayer != nil {
		return errors.New("ethernet layer already exists")
	}

	var srcMAC, dstMAC net.HardwareAddr

	//MAC address of the source
	srcMAC, _ = net.ParseMAC(srcMACstr)

	if srcMAC == nil {
		return errors.New("no source mac given")
	}

	//MAC address of the destination
	dstMAC, _ = net.ParseMAC(dstMACstr)

	if dstMAC == nil {
		return errors.New("no destination mac given")
	}

	//Ethernet packet header
	p.ethernetLayer = &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	return nil
}

//GetEthernetPacket returns the ethernet layer created
func (p *Packet) GetEthernetPacket() layers.Ethernet {

	return *p.ethernetLayer
}

//AddIPLayer creates an IP layer
func (p *Packet) AddIPLayer(srcIPstr string, dstIPstr string) error {

	if p.ipLayer != nil {
		return errors.New("ip layer already exists")
	}

	var srcIP, dstIP net.IP

	//IP address of the source
	srcIP = net.ParseIP(srcIPstr)

	if srcIP == nil {
		return errors.New("no source ip given")
	}

	//IP address of the destination
	dstIP = net.ParseIP(dstIPstr)

	if dstIP == nil {
		return errors.New("no destination ip given")
	}

	//IP packet header
	p.ipLayer = &layers.IPv4{
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

	return p.ipLayer.Checksum
}

//GetIPPacket returns IP checksum
func (p *Packet) GetIPPacket() layers.IPv4 {

	return *p.ipLayer
}

//AddTCPLayer creates a TCP layer
func (p *Packet) AddTCPLayer(srcPort layers.TCPPort, dstPort layers.TCPPort) error {

	if p.tcpLayer != nil {
		return errors.New("tcp layer already exists")
	}

	if srcPort == 0 {
		return errors.New("no source tcp port given")
	}

	if dstPort == 0 {
		return errors.New("no destination tcp port given")
	}

	//TCP packet header
	p.tcpLayer = &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Window:  0,
		Urgent:  0,
		Seq:     0,
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

	return p.tcpLayer.SetNetworkLayerForChecksum(p.ipLayer)
}

//GetTCPPacket returns created TCP packet
func (p *Packet) GetTCPPacket() layers.TCP {

	return *p.tcpLayer
}

//GetTCPSequenceNumber returns TCP Sequence number
func (p *Packet) GetTCPSequenceNumber() uint32 {

	return p.tcpLayer.Seq
}

//GetTCPAcknowledgementNumber returns TCP Acknowledgement number
func (p *Packet) GetTCPAcknowledgementNumber() uint32 {

	return p.tcpLayer.Ack
}

//GetTCPWindow returns TCP Window
func (p *Packet) GetTCPWindow() uint16 {

	return p.tcpLayer.Window
}

//GetTCPSyn returns TCP SYN flag
func (p *Packet) GetTCPSyn() bool {

	return p.tcpLayer.SYN
}

//GetTCPAck returns TCP ACK flag
func (p *Packet) GetTCPAck() bool {

	return p.tcpLayer.ACK
}

//GetTCPFin returns TCP FIN flag
func (p *Packet) GetTCPFin() bool {

	return p.tcpLayer.FIN
}

//GetTCPChecksum returns TCP checksum
func (p *Packet) GetTCPChecksum() uint16 {

	return p.tcpLayer.Checksum
}

//SetTCPSequenceNumber changes TCP sequence number
func (p *Packet) SetTCPSequenceNumber(seqNum uint32) {

	p.tcpLayer.Seq = seqNum

}

//SetTCPAcknowledgementNumber changes TCP Acknowledgement number
func (p *Packet) SetTCPAcknowledgementNumber(ackNum uint32) {

	p.tcpLayer.Ack = ackNum

}

//SetTCPWindow changes the TCP window
func (p *Packet) SetTCPWindow(window uint16) {

	p.tcpLayer.Window = window

}

//SetTCPSyn changes the TCP SYN flag to true
func (p *Packet) SetTCPSyn() {

	p.tcpLayer.SYN = true
	p.tcpLayer.ACK = false
	p.tcpLayer.FIN = false
}

//SetTCPSynAck changes the TCP SYN and ACK flag to true
func (p *Packet) SetTCPSynAck() {

	p.tcpLayer.SYN = true
	p.tcpLayer.ACK = true
	p.tcpLayer.FIN = false
}

//SetTCPAck changes the TCP ACK flag to true
func (p *Packet) SetTCPAck() {

	p.tcpLayer.SYN = false
	p.tcpLayer.ACK = true
	p.tcpLayer.FIN = false
}

//SetTCPCwr changes the TCP CWR flag to true
func (p *Packet) SetTCPCwr() {
	p.tcpLayer.CWR = true
}

//SetTCPEce changes the TCP ECE flag to true
func (p *Packet) SetTCPEce() {
	p.tcpLayer.ECE = true
}

//SetTCPUrg changes the TCP URG flag to true
func (p *Packet) SetTCPUrg() {
	p.tcpLayer.URG = true
}

//SetTCPPsh changes the TCP PSH flag to true
func (p *Packet) SetTCPPsh() {
	p.tcpLayer.PSH = true
}

//SetTCPRst changes the TCP RST flag to true
func (p *Packet) SetTCPRst() {
	p.tcpLayer.RST = true
}

//SetTCPFin changes the TCP FIN flag to true
func (p *Packet) SetTCPFin() {
	p.tcpLayer.FIN = true
}

//NewTCPPayload adds new payload to TCP layer
func (p *Packet) NewTCPPayload(newPayload string) error {

	if p.tcpLayer.Payload != nil {
		return errors.New("payload already exists")
	}

	p.tcpLayer.Payload = []byte(newPayload)

	return nil
}

//ToBytes creates a packet buffer and converts it into a complete packet with ethernet, IP and TCP (with options)
func (p *Packet) ToBytes() ([]byte, error) {

	opts := gopacket.SerializeOptions{
		FixLengths:       true, //fix lengths based on the payload (data)
		ComputeChecksums: true, //compute checksum based on the payload during serialization
	}

	if err := p.tcpLayer.SetNetworkLayerForChecksum(p.ipLayer); err != nil {
		return nil, fmt.Errorf("unable to compute checksum: %s", err)
	}

	//Creating a packet buffer by serializing the ethernet, IP and TCP layers/packets
	packetBuf := gopacket.NewSerializeBuffer()
	tcpPayload := gopacket.Payload(p.tcpLayer.Payload)
	if err := gopacket.SerializeLayers(packetBuf, opts, p.ethernetLayer, p.ipLayer, p.tcpLayer, tcpPayload); err != nil {
		return nil, fmt.Errorf("unable to serialize layers: %s", err)
	}
	//Converting into bytes and removing the ethernet from the layers
	bytes := packetBuf.Bytes()
	bytesWithoutEthernet := bytes[14:]

	var finalBytes []byte
	finalBytes = append(finalBytes, bytesWithoutEthernet...)

	return finalBytes, nil
}

//NewTemplateFlow will return flow of packets which implements PacketManipulator
func NewTemplateFlow() PacketFlowManipulator {

	return &PacketFlow{}
}

//AddPacket is a helper method to add the packet from the template to the struct internal struct field
func (p *Packet) AddPacket(packet gopacket.Packet) {

	p.packet = packet

}

//DecodePacket returns decoded packet which implements PacketManipulator
func (p *Packet) DecodePacket() PacketManipulator {

	packetData := &Packet{
		ethernetLayer: &layers.Ethernet{},
		ipLayer:       &layers.IPv4{},
		tcpLayer:      &layers.TCP{},
	}

	newEthernetPacket := packetData.GetEthernetPacket()
	newIPPacket := packetData.GetIPPacket()
	newTCPPacket := packetData.GetTCPPacket()

	if ethernetLayer := p.packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		ethernet, _ := ethernetLayer.(*layers.Ethernet)
		newEthernetPacket.SrcMAC = ethernet.SrcMAC
		newEthernetPacket.DstMAC = ethernet.DstMAC
		newEthernetPacket.EthernetType = ethernet.EthernetType
	}

	if ipLayer := p.packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		newIPPacket.SrcIP = ip.SrcIP
		newIPPacket.DstIP = ip.DstIP
		newIPPacket.Version = ip.Version
		newIPPacket.Length = ip.Length
		newIPPacket.Protocol = ip.Protocol
		newIPPacket.TTL = ip.TTL
	}

	if tcpLayer := p.packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)

		newTCPPacket.SrcPort = tcp.SrcPort
		newTCPPacket.DstPort = tcp.DstPort
		newTCPPacket.Seq = tcp.Seq
		newTCPPacket.Ack = tcp.Ack
		newTCPPacket.SYN = tcp.SYN
		newTCPPacket.FIN = tcp.FIN
		newTCPPacket.RST = tcp.RST
		newTCPPacket.PSH = tcp.PSH
		newTCPPacket.ACK = tcp.ACK
		newTCPPacket.URG = tcp.URG
		newTCPPacket.ECE = tcp.ECE
		newTCPPacket.CWR = tcp.CWR
		newTCPPacket.NS = tcp.NS
		newTCPPacket.Checksum = tcp.Checksum
		newTCPPacket.Window = tcp.Window
	}

	packetData = &Packet{
		ethernetLayer: &newEthernetPacket,
		ipLayer:       &newIPPacket,
		tcpLayer:      &newTCPPacket,
	}

	return packetData
}

//NewPacketFlow returns PacketFlow struct which implements PacketFlowManipulator
func NewPacketFlow(smac string, dmac string, sip string, dip string, sport layers.TCPPort, dport layers.TCPPort) PacketFlowManipulator {

	initialTupules := &PacketFlow{
		sMAC:  smac,
		dMAC:  dmac,
		sIP:   sip,
		dIP:   dip,
		sPort: sport,
		dPort: dport,
		flow:  make([]PacketManipulator, 0),
	}

	return initialTupules
}

//GenerateTCPFlow returns an array of PacketFlowManipulator interface
func (p *PacketFlow) GenerateTCPFlow(pt PacketFlowType) (PacketFlowManipulator, error) {

	if pt == 0 {
		//Create a SYN packet to initialize the flow
		firstPacket := NewPacket()
		if err := firstPacket.AddEthernetLayer(p.sMAC, p.dMAC); err != nil {
			return nil, fmt.Errorf("unable tp add ethernet layer: %s", err)
		}
		if err := firstPacket.AddIPLayer(p.sIP, p.dIP); err != nil {
			return nil, fmt.Errorf("unable to add ip layer: %s", err)
		}
		if err := firstPacket.AddTCPLayer(p.sPort, p.dPort); err != nil {
			return nil, fmt.Errorf("unable to add tcp layer: %s", err)
		}
		firstPacket.SetTCPSyn()
		firstPacket.SetTCPSequenceNumber(firstPacket.GetTCPSequenceNumber())
		firstPacket.SetTCPAcknowledgementNumber(firstPacket.GetTCPAcknowledgementNumber())
		synPacket, _ := firstPacket.(*Packet)

		p.flow = append(p.flow, synPacket)

		//Create a SynAck packet
		secondPacket := NewPacket()
		if err := secondPacket.AddEthernetLayer(p.sMAC, p.dMAC); err != nil {
			return nil, fmt.Errorf("unable to add ethernet layer: %s", err)
		}
		if err := secondPacket.AddIPLayer(p.dIP, p.sIP); err != nil {
			return nil, fmt.Errorf("unable to add ip layer: %s", err)
		}
		if err := secondPacket.AddTCPLayer(p.dPort, p.sPort); err != nil {
			return nil, fmt.Errorf("unable to add tcp layer: %s", err)
		}
		secondPacket.SetTCPSynAck()
		secondPacket.SetTCPSequenceNumber(0)
		secondPacket.SetTCPAcknowledgementNumber(firstPacket.GetTCPSequenceNumber() + 1)
		synackPacket, _ := secondPacket.(*Packet)

		p.flow = append(p.flow, synackPacket)

		//Create an Ack Packet
		thirdPacket := NewPacket()
		if err := thirdPacket.AddEthernetLayer(p.sMAC, p.dMAC); err != nil {
			return nil, fmt.Errorf("unable tp add ethernet layer: %s", err)
		}
		if err := thirdPacket.AddIPLayer(p.sIP, p.dIP); err != nil {
			return nil, fmt.Errorf("unable to add ip layer: %s", err)
		}
		if err := thirdPacket.AddTCPLayer(p.sPort, p.dPort); err != nil {
			return nil, fmt.Errorf("unable to add tcp layer: %s", err)
		}
		thirdPacket.SetTCPAck()
		thirdPacket.SetTCPSequenceNumber(secondPacket.GetTCPAcknowledgementNumber())
		thirdPacket.SetTCPAcknowledgementNumber(secondPacket.GetTCPSequenceNumber() + 1)
		ackPacket, _ := thirdPacket.(*Packet)

		p.flow = append(p.flow, ackPacket)

		return p, nil

	} else if pt == 1 {

		for i := 0; i < len(PacketFlowTemplate1); i++ {
			//Create a Packet type variable to store decoded packet
			newPacket := NewPacket()
			packet := gopacket.NewPacket(PacketFlowTemplate1[i], layers.LayerTypeEthernet, gopacket.Default)
			newPacket.AddPacket(packet)

			p.flow = append(p.flow, newPacket.DecodePacket())

		}

		return p, nil
	} else if pt == 2 {

		for i := 0; i < len(PacketFlowTemplate2); i++ {

			//Create a Packet type variable to store decoded packet
			newPacket := NewPacket()
			packet := gopacket.NewPacket(PacketFlowTemplate2[i], layers.LayerTypeEthernet, gopacket.Default)
			newPacket.AddPacket(packet)

			p.flow = append(p.flow, newPacket.DecodePacket())

		}

		return p, nil
	} else if pt == 3 {

		for i := 0; i < len(PacketFlowTemplate3); i++ {

			//Create a Packet type variable to store decoded packet
			newPacket := NewPacket()
			packet := gopacket.NewPacket(PacketFlowTemplate3[i], layers.LayerTypeEthernet, gopacket.Default)
			newPacket.AddPacket(packet)

			p.flow = append(p.flow, newPacket.DecodePacket())

		}

		return p, nil
	}

	return nil, nil
}

//GenerateTCPFlowPayload Coming soon...
func (p *PacketFlow) GenerateTCPFlowPayload(newPayload string) PacketFlowManipulator {

	return nil
}

//AppendPacket adds the packet to Flow field of PacketFlowManipulator interface
func (p *PacketFlow) AppendPacket(pm PacketManipulator) int {

	p.flow = append(p.flow, pm)

	return p.GetNumPackets()
}

//GetMatchPackets implicitly returns the matching packets requested by the user
func (p *PacketFlow) getMatchPackets(syn, ack, fin bool) PacketFlowManipulator {

	packetsInFlow := NewPacketFlow(p.sMAC, p.dMAC, p.sIP, p.dIP, p.sPort, p.dPort)

	for j := 0; j < len(p.flow); j++ {
		if p.flow[j].GetTCPSyn() == syn && p.flow[j].GetTCPAck() == ack && p.flow[j].GetTCPFin() == fin {
			packetsInFlow.AppendPacket(p.flow[j])
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

//GetUptoFirstSynAckPacket will return packets upto first SynAck packet
func (p *PacketFlow) GetUptoFirstSynAckPacket() PacketFlowManipulator {

	packetsInFlow := NewPacketFlow(p.sMAC, p.dMAC, p.sIP, p.dIP, p.sPort, p.dPort)
	flag := false

	for j := 0; j < len(p.flow); j++ {
		if !flag {
			packetsInFlow.AppendPacket(p.flow[j])
			if p.flow[j].GetTCPSyn() && p.flow[j].GetTCPAck() && !p.flow[j].GetTCPFin() {
				flag = true
			}
		}
	}

	return packetsInFlow
}

//GetUptoFirstAckPacket will return packets upto first Ack packet
func (p *PacketFlow) GetUptoFirstAckPacket() PacketFlowManipulator {

	packetsInFlow := NewPacketFlow(p.sMAC, p.dMAC, p.sIP, p.dIP, p.sPort, p.dPort)
	flag := false

	for j := 0; j < len(p.flow); j++ {
		if !flag {
			packetsInFlow.AppendPacket(p.flow[j])
			if !p.flow[j].GetTCPSyn() && p.flow[j].GetTCPAck() && !p.flow[j].GetTCPFin() {
				flag = true
			}
		}
	}

	return packetsInFlow
}

//GetNthPacket returns the packet requested by the user from the array
func (p *PacketFlow) GetNthPacket(index int) PacketManipulator {

	for i := 0; i < len(p.flow); i++ {
		if index == i {
			return p.flow[i]
		}
	}

	panic("Index out of range")
}

//GetNumPackets returns an array of packets
func (p *PacketFlow) GetNumPackets() int {

	return len(p.flow)
}
