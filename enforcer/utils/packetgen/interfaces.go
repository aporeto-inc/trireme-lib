package packetgen

import "github.com/google/gopacket/layers"

//PacketFlowType type  for different types of flows
type PacketFlowType uint8

const (
	//PacketFlowTypeGoodFlow returns a good flow
	PacketFlowTypeGoodFlow PacketFlowType = iota
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
	SetTCPSequenceNumber(seqNum uint32) error
	//Used to set TCP Acknowledgement number
	SetTCPAcknowledgementNumber(ackNum uint32) error
	//Used to set TCP Window
	SetTCPWindow(window uint16) error
	//Used to set TCP Syn flag to true
	SetTCPSyn()
	//Used to set TCP Syn and Ack flag to true
	SetTCPSynAck()
	//Used to set TCP Ack flag to true
	SetTCPAck()
	//Used to add TCP Payload
	NewTCPPayload(newPayload string) error
}

//PacketHelper interface is a helper for packets and packet flows
//Optional: not needed for actual usage
type PacketHelper interface {
	ToBytes() []byte
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
	//Ued to create a flow of TCP packets
	GenerateTCPFlow(pt PacketFlowType) PacketFlowManipulator
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
	//Used to return Nth packet from the flow
	GetNthPacket(index int) PacketManipulator
	//Used to return length of the flow
	GetNumPackets() int
	//Used to add a new packet to the flow
	AppendPacket(p PacketManipulator) int
}

//Packet is a custom type which holds the packets and implements PacketManipulator
type Packet struct {
	EthernetLayer *layers.Ethernet
	IPLayer       *layers.IPv4
	TCPLayer      *layers.TCP
}

//PacketFlow is a custom type which holds the packet attributes and the flow
//Implements PacketFlowManipulator interface
type PacketFlow struct {
	sMAC  string
	dMAC  string
	sIP   string
	dIP   string
	sPort layers.TCPPort
	dPort layers.TCPPort
	Flow  []PacketManipulator
}
