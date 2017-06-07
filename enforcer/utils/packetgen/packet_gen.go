package packetgen

import "github.com/google/gopacket/layers"

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
	NewTCPPayload(newPayload string) error
	GetTCPChecksum() uint16
}

func NewPacket() PacketManipulator {
	return &Packet{}
}

func NewIPPacket(sip, dip string) PacketManipulator {
	p := NewPacket()
	p.AddIPLayer(sip, dip)
	return p
}

func NewIPTCPPacket(sip, dip, sport, dport string) PacketManipulator {
	p := NewIPPacket(sip, dip)
	// p.AddTCPLayer(sport, dport)
	return p
}

func (p *Packet) AddIPLayer(srcIPstr string, dstIPstr string) error {
	return nil
}

func (p *Packet) GetIPChecksum() uint16 {
	return 0
}

func (p *Packet) AddTCPLayer(srcPort layers.TCPPort, dstPort layers.TCPPort) error {
	return nil
}

func (p *Packet) ChangeTCPSequenceNumber(seqNum uint32) error {
	return nil
}

func (p *Packet) ChangeTCPAcknowledgementNumber(ackNum uint32) error {
	return nil
}

func (p *Packet) ChangeTCPWindow(window uint16) error {
	return nil
}

func (p *Packet) SetTCPSyn() error {
	return nil
}

func (p *Packet) SetTCPSynAck() error {
	return nil
}

func (p *Packet) SetTCPAck() error {
	return nil
}

func (p *Packet) NewTCPPayload(newPayload string) error {
	return nil
}

func (p *Packet) GetTCPChecksum() uint16 {
	return 0
}
