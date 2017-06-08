package packetgen

import "github.com/google/gopacket/layers"

//PacketFlowType ...
type PacketFlowType uint8

const (
	//PacketFlowTypeGoodFlow returns a good flow
	PacketFlowTypeGoodFlow PacketFlowType = iota
)

//EthernetPacketManipulator is used to create/manipulate Ethernet packet
type EthernetPacketManipulator interface {
	AddEthernetLayer(srcMACstr string, dstMACstr string) error
	GetEthernetPacket() layers.Ethernet
}

//IPPacketManipulator is used to create/manipulate IP packet
type IPPacketManipulator interface {
	AddIPLayer(srcIPstr string, dstIPstr string) error
	GetIPPacket() layers.IPv4
	GetIPChecksum() uint16
}

//TCPPacketManipulator is used to create/manipulate TCP packet
type TCPPacketManipulator interface {
	AddTCPLayer(srcPort layers.TCPPort, dstPort layers.TCPPort) error
	GetTCPPacket() layers.TCP
	GetTCPSequenceNumber() uint32
	GetTCPAcknowledgementNumber() uint32
	GetTCPWindow() uint16
	GetTCPSyn() bool
	GetTCPAck() bool
	GetTCPFin() bool
	GetTCPChecksum() uint16

	SetTCPSequenceNumber(seqNum uint32) error
	SetTCPAcknowledgementNumber(ackNum uint32) error
	SetTCPWindow(window uint16) error
	SetTCPSyn()
	SetTCPSynAck()
	SetTCPAck()

	NewTCPPayload(newPayload string) error
}

//PacketHelper is a helper for the packets
type PacketHelper interface {
	ToBytes() []byte
}

// PacketManipulator is an interface for packet manipulations
type PacketManipulator interface {
	EthernetPacketManipulator
	IPPacketManipulator
	TCPPacketManipulator
	PacketHelper
}

// PacketFlowManipulator is an interface to packet flow manipulations
type PacketFlowManipulator interface {
	GenerateTCPFlow(pt PacketFlowType) PacketFlowManipulator
	GetSynPackets() PacketFlowManipulator
	GetSynAckPackets() PacketFlowManipulator
	GetAckPackets() PacketFlowManipulator
	GetNthPacket(index int) PacketManipulator
	GetNumPackets() int
	AppendPacket(p PacketManipulator) int
}

//Packet is a type to packet
type Packet struct {
	EthernetLayer *layers.Ethernet
	IPLayer       *layers.IPv4
	TCPLayer      *layers.TCP
}

//PacketFlow is a type to packet flows
type PacketFlow struct {
	sMAC  string
	dMAC  string
	sIP   string
	dIP   string
	sPort layers.TCPPort
	dPort layers.TCPPort
	Flow  []PacketManipulator
}
