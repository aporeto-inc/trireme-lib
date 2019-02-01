package packettracing

type TracingDirection int

const (
	Disabled        TracingDirection = 0
	NetworkOnly     TracingDirection = 1
	ApplicationOnly TracingDirection = 2
	Invalid         TracingDirection = 4
)

type PacketEvent string

const (
	PacketDropped  PacketEvent = "Dropped"
	PacketReceived PacketEvent = "Received"
	PacketSent     PacketEvent = "Transmitted"
)

func IsNetworkPacketTraced(direction TracingDirection) bool {
	return (direction&NetworkOnly != 0)
}

func IsApplicationPacketTraced(direction TracingDirection) bool {
	return (direction&ApplicationOnly != 0)
}
