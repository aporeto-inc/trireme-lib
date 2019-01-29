package packettracing

type TracingDirection int

const (
	Disabled        TracingDirection = 0
	NetworkOnly     TracingDirection = 1
	ApplicationOnly TracingDirection = 2
	Invalid         TracingDirection = 4
)
