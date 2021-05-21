package constants

const (
	//Initialmarkval is the start of mark values we assign to cgroup
	Initialmarkval = 100
	// EnforcerCgroupMark is the net_cls.classid that is programmed for the cgroup that all enforcer processes belong to
	EnforcerCgroupMark = 1536
	//PacketMarkToSetConnmark is used to set mark on packet when repeating a packet through nfq.
	PacketMarkToSetConnmark = uint32(0x42)
	//DefaultInputMark is used to set mark on packet when repeating a packet through nfq.
	DefaultInputMark = uint32(0x43)
	// DefaultConnMark is the default conn mark for all data packets
	DefaultConnMark = uint32(0xEEEE)
	// DefaultExternalConnMark is the default conn mark for all data packets
	DefaultExternalConnMark = uint32(0xEEEF)
	// DeleteConnmark is the mark used to trigger udp handshake.
	DeleteConnmark = uint32(0xABCD)
	// DropConnmark is used to drop packets identified by acl's
	DropConnmark = uint32(0xEEED)
	// HandshakeConnmark is used to drop response packets
	HandshakeConnmark = uint32(0xEEEC)
	// IstioPacketMark is a mark that we use so that we don't loop in the Istio Chain forever.
	IstioPacketMark = 0x44
)
