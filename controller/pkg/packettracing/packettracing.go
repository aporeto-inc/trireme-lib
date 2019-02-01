package packettracing

type TracingDirection int

const (
	Disabled        TracingDirection = 0
	NetworkOnly     TracingDirection = 1
	ApplicationOnly TracingDirection = 2
	Invalid         TracingDirection = 4
)

type packetEvent string

const (
	PacketDropped  packetEvent = "Dropped"
	PacketReceived packetEvent = "Received"
	PacketSent     packetEvent = "Transmitted"
)

func IsNetworkPacketTraced(direction TracingDirection) bool {
	return (direction&NetworkOnly != 0)
}

func IsApplicationPacketTraced(direction TracingDirection) bool {
	return (direction&ApplicationOnly != 0)
}

type PacketReport struct {
	TCPFlags        int
	Claims          map[string]string
	DestinationIP   string
	DestinationPort int
	DropReason      string
	Encrypt         bool
	Event           packetEvent
	Length          int
	Mark            int
	Namespace       string
	PacketID        int
	Protocol        int
	PUID            string
	SourceIP        string
	SourcePort      int
	TriremePacket   bool
}
