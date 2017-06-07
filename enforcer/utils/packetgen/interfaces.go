package packetgen

import "github.com/google/gopacket/layers"

// type Pkt interface {
// 	GenerateIPPacket(srcIPstr string, dstIPstr string) layers.IPv4
// 	GenerateTCPPacket(ip *layers.IPv4, srcPort layers.TCPPort, dstPort layers.TCPPort) layers.TCP
// 	ChangeSequenceNumber(seqNum uint32) layers.TCP
// 	ChangeAcknowledgementNumber(ackNum uint32) layers.TCP
// 	ChangeWindow(window uint16) layers.TCP
// 	SetSynTrue() layers.TCP
// 	SetSynAckTrue() layers.TCP
// 	SetAckTrue() layers.TCP
// 	ChangePayload(newPayload string) layers.TCP
// 	GetChecksum() uint16
// }

// PacketManipulator is an interface for packet manipulations
type PacketManipulator interface {
	AddIPLayer(srcIPstr string, dstIPstr string) error
	GetIPChecksum() uint16

	AddTCPLayer(srcPort layers.TCPPort, dstPort layers.TCPPort) error
	ChangeTCPSequenceNumber(seqNum uint32) error
	ChangeTCPAcknowledgementNumber(ackNum uint32) error
	ChangeTCPWindow(window uint16) error
	SetTCPSyn() error
	SetTCPSynAck() error
	SetTCPAck() error
	GetTCPSyn() bool
	GetTCPFin() bool
	GetTCPAck() bool
	NewTCPPayload(newPayload string) error
	GetTCPChecksum() uint16
	ToBytes() [][]byte
	GetIPPacket() layers.IPv4
	GetTCPPacket() layers.TCP
	DisplayTCPPacket()
}

// PacketFlowManipulator is an interface to ..
type PacketFlowManipulator interface {
	GenerateTCPFlow(bytePacket [][]byte) []PacketManipulator
	GenerateTCPFlowPayload(newPayload string) [][]byte
	//GenerateInvalidTCPFlow() [][]byte
	GetSynPackets() []PacketManipulator
	GetSynAckPackets() [][]byte
	GetAckPackets() [][]byte
	GetNthPacket(index int) PacketManipulator
}

// Packet is a type to ...
type Packet struct {
	IPLayer  *layers.IPv4
	TCPLayer *layers.TCP
}

//PacketFlow is a type to ...
type PacketFlow struct {
	SIP   string
	DIP   string
	SPort layers.TCPPort
	DPort layers.TCPPort
	Flow  []PacketManipulator
}
