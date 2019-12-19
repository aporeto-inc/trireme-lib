package packetgen

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//PacketFlowType type  for different types of flows
type PacketFlowType uint8

const (
	//PacketFlowTypeGenerateGoodFlow is used to generate a good floe
	PacketFlowTypeGenerateGoodFlow PacketFlowType = iota
	//PacketFlowTypeGoodFlowTemplate will have a good flow from a hardcoded template
	PacketFlowTypeGoodFlowTemplate
	//PacketFlowTypeMultipleGoodFlow will have two flows
	PacketFlowTypeMultipleGoodFlow
	//PacketFlowTypeMultipleIntervenedFlow will have two flows intervened to eachothers
	PacketFlowTypeMultipleIntervenedFlow
)

//EthernetPacketManipulator interface is used to create/manipulate Ethernet packet
type EthernetPacketManipulator interface {
	//Used to create an Ethernet layer
	AddEthernetLayer(srcMACstr string, dstMACstr string) error
	//Used to return Ethernet packet created
	GetEthernetPacket() layers.Ethernet
}

//IPPacketManipulator interface is used to create/manipulate IP packet
type IPPacketManipulator interface {
	//Used to create an IP layer
	AddIPLayer(srcIPstr string, dstIPstr string) error
	//Used to return IP packet created
	GetIPPacket() layers.IPv4
	//Used to return IP checksum
	GetIPChecksum() uint16
}

//TCPPacketManipulator interface is used to create/manipulate TCP packet
type TCPPacketManipulator interface {
	//Used to create a TCP layer
	AddTCPLayer(srcPort layers.TCPPort, dstPort layers.TCPPort) error
	//Used to return TCP packet
	GetTCPPacket() layers.TCP
	//Used to return TCP Sequence number
	GetTCPSequenceNumber() uint32
	//Used to return TCP Acknowledgement number number
	GetTCPAcknowledgementNumber() uint32
	//Used to return TCP window
	GetTCPWindow() uint16
	//Used to return TCP Syn flag
	GetTCPSyn() bool
	//Used to return TCP Ack flag
	GetTCPAck() bool
	//Used to return TCP Fin flag
	GetTCPFin() bool
	//Used to return TCP Checksum
	GetTCPChecksum() uint16
	//Used to set TCP Sequence number
	SetTCPSequenceNumber(seqNum uint32)
	//Used to set TCP Acknowledgement number
	SetTCPAcknowledgementNumber(ackNum uint32)
	//Used to set TCP Window
	SetTCPWindow(window uint16)
	//Used to set TCP Syn flag to true
	SetTCPSyn()
	//Used to set TCP Syn and Ack flag to true
	SetTCPSynAck()
	//Used to set TCP Ack flag to true
	SetTCPAck()
	//Used to set TCP Cwr flag to true
	SetTCPCwr()
	//Used to set TCP Ece flag to true
	SetTCPEce()
	//Used to set TCP Urg flag to true
	SetTCPUrg()
	//Used to set TCP Psh flag to true
	SetTCPPsh()
	//Used to set TCP Rst flag to true
	SetTCPRst()
	//Used to set TCP Fin flag to true
	SetTCPFin()
	//Used to add TCP Payload
	NewTCPPayload(newPayload string) error
}

//PacketHelper interface is a helper for packets and packet flows
//Optional: not needed for actual usage
type PacketHelper interface {
	ToBytes() ([]byte, error)
	AddPacket(packet gopacket.Packet)
	DecodePacket() PacketManipulator
}

//PacketManipulator is an interface for packet manipulations
//Composition of Ethernet, IP and TCP Manipulator interface
type PacketManipulator interface {
	EthernetPacketManipulator
	IPPacketManipulator
	TCPPacketManipulator
	PacketHelper
}

//PacketFlowManipulator is an interface for packet flow manipulations
//Used to create/manipulate packet flows
type PacketFlowManipulator interface {
	//Used to create a flow of TCP packets
	GenerateTCPFlow(pt PacketFlowType) (PacketFlowManipulator, error)
	//Used to return first TCP Syn packet
	GetFirstSynPacket() PacketManipulator
	//Used to return first TCP SynAck packet
	GetFirstSynAckPacket() PacketManipulator
	//Used to return first TCP Ack packet
	GetFirstAckPacket() PacketManipulator
	//Used to return all the TCP Syn packets from the flow
	GetSynPackets() PacketFlowManipulator
	//Used to return all the TCP SynAck packets from the flow
	GetSynAckPackets() PacketFlowManipulator
	//Used to return all the TCP Ack packets from the flow
	GetAckPackets() PacketFlowManipulator
	//Used to return all the packets upto first TCP SynAck packet from the flow
	GetUptoFirstSynAckPacket() PacketFlowManipulator
	//Used to return all the packets upto first TCP Ack packet from the flow
	GetUptoFirstAckPacket() PacketFlowManipulator
	//Used to return Nth packet from the flow
	GetNthPacket(index int) PacketManipulator
	//Used to return length of the flow
	GetNumPackets() int
	//Used to add a new packet to the flow
	AppendPacket(p PacketManipulator) int
}

//Packet is a custom type which holds the packets and implements PacketManipulator
type Packet struct {
	ethernetLayer *layers.Ethernet
	ipLayer       *layers.IPv4
	tcpLayer      *layers.TCP
	packet        gopacket.Packet
}

//PacketFlow is a custom type which holds the packet attributes and the flow
//Implements PacketFlowManipulator interface
type PacketFlow struct {
	sMAC, dMAC   string
	sIP, dIP     string
	sPort, dPort layers.TCPPort
	flow         []PacketManipulator
}
