package packetgen

import "github.com/google/gopacket/layers"

//IPPacketManipulator is used to create/manipulate IP packet
type IPPacketManipulator interface {
	AddIPLayer(srcIPstr string, dstIPstr string) error
	GetIPChecksum() uint16
	GetIPPacket() layers.IPv4
}

//TCPPacketManipulator is used to create/manipulate TCP packet
type TCPPacketManipulator interface {
	AddTCPLayer(srcPort layers.TCPPort, dstPort layers.TCPPort) error
	GetTCPPacket() layers.TCP
	GetTCPSyn() bool
	GetTCPFin() bool
	GetTCPAck() bool
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
	ToBytes() [][]byte
}

// PacketManipulator is an interface for packet manipulations
type PacketManipulator interface {
	IPPacketManipulator
	TCPPacketManipulator
	PacketHelper
}

// PacketFlowManipulator is an interface to packet flow manipulations
type PacketFlowManipulator interface {
	GenerateTCPFlow(bytePacket [][]byte) PacketFlowManipulator
	GenerateTCPFlowPayload(newPayload string) PacketFlowManipulator
	//GenerateInvalidTCPFlow() [][]byte
	GetSynPackets() PacketFlowManipulator
	GetSynAckPackets() PacketFlowManipulator
	GetAckPackets() PacketFlowManipulator
	GetNthPacket(index int) PacketManipulator
	AddPacket(p PacketManipulator)
}

//Packet is a type to packet
type Packet struct {
	IPLayer  *layers.IPv4
	TCPLayer *layers.TCP
}

//PacketFlow is a type to packet flows
type PacketFlow struct {
	SIP   string
	DIP   string
	SPort layers.TCPPort
	DPort layers.TCPPort
	Flow  []PacketManipulator
}
