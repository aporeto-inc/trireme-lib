package enforcer_adaptor

// FilterQueue captures all the configuration parameters of the NFQUEUEs
type FilterQueue struct {
	// Network Queue is the queue number of the base queue for network packets
	NetworkQueue uint16
	// NetworkQueueSize is the size of the network queue
	NetworkQueueSize uint32
	// NumberOfNetworkQueues is the number of network queues allocated
	NumberOfNetworkQueues uint16
	// ApplicationQueue is the queue number of the first application queue
	ApplicationQueue uint16
	// ApplicationQueueSize is the size of the application queue
	ApplicationQueueSize uint32
	// NumberOfApplicationQueues is the number of queues that must be allocated
	NumberOfApplicationQueues uint16
}

var (
	// TransmitterLabel is the name of the label used to identify the Transmitter Context
	TransmitterLabel = "AporetoContextID"
)

type PacketStats struct {
	IncomingPackets uint32
	OutgoingPackets uint32

	CreateDropPackets      uint32
	AuthDropPackets        uint32
	ServicePreDropPackets  uint32
	ServicePostDropPackets uint32
}
