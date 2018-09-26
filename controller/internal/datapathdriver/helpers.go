package datapathdriver

// Payload returns the packet payload
func (p *Packet) Payload() []byte {
	return p.packetPayload
}

// Mark returns the mark on the packet
func (p *Packet) Mark() uint32 {
	return uint32(p.mark)
}

// PacketID returns the packet id
func (p *Packet) PacketID() uint32 {
	return uint32(p.packetID)
}
