package packettracing

// TracingDirection is used to configure the direction for which we want to trace packets
type TracingDirection int

// TracingDirection enum all possible states
const (
	Disabled        TracingDirection = 0
	NetworkOnly     TracingDirection = 1
	ApplicationOnly TracingDirection = 2
	Invalid         TracingDirection = 4
)

// PacketEvent is string for our packet decision
type PacketEvent string

// Enum for all packetevents
const (
	PacketDropped  PacketEvent = "Dropped"
	PacketReceived PacketEvent = "Received"
	PacketSent     PacketEvent = "Transmitted"
)

// IsNetworkPacketTraced checks if network mode packet tracign is enabled
func IsNetworkPacketTraced(direction TracingDirection) bool {
	return (direction&NetworkOnly != 0)
}

// IsApplicationPacketTraced checks if application
func IsApplicationPacketTraced(direction TracingDirection) bool {
	return (direction&ApplicationOnly != 0)
}
