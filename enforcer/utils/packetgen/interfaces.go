package packetgen

import (
	"net"

	"github.com/google/gopacket/layers"
)

type Pkt interface {
	GenerateIPPacket(srcIPstr string, dstIPstr string) layers.IPv4
	GenerateTCPPacket(ip *layers.IPv4, srcPort layers.TCPPort, dstPort layers.TCPPort) layers.TCP
	ChangeSequenceNumber(seqNum uint32) layers.TCP
	ChangeAcknowledgementNumber(ackNum uint32) layers.TCP
	ChangeWindow(window uint16) layers.TCP
	SetSynTrue() layers.TCP
	SetSynAckTrue() layers.TCP
	SetAckTrue() layers.TCP
	ChangePayload(newPayload string) layers.TCP
	GetChecksum() uint16
}

type PktFlow interface {
	GenerateTCPFlow(bytePacket [][]byte) [][]byte
	GenerateTCPFlowPayload(newPayload string) [][]byte
	//GenerateInvalidTCPFlow() [][]byte
	GetSynPackets() [][]byte
	GetSynAckPackets() [][]byte
	GetAckPackets() [][]byte
}

type Packet struct {
	IPLayer            layers.IPv4
	TCPLayer           layers.TCP
	SequenceNum        uint32
	AcknowledgementNum uint32
	Window             uint16
	SrcIPstr, DstIPstr string
	SrcIP, DstIP       net.IP
	SrcPort, DstPort   layers.TCPPort
	Layers             [150]layers.TCP
}

type PacketFlow struct {
	Packet
	GeneratedFlow [][]byte
	TemplateFlow  [][]byte
}
