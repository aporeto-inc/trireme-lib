package enforcer

// FilterQueue captures all the configuration parameters of the NFQUEUEs
type FilterQueue struct {
	// MarkValue is the default mark to set in packets in the RAW chain
	MarkValue int
	// Network Queue is the queue number of the base queue for network packets
	NetworkQueue uint16
	// NumberOfApplicationQueues is the number of queues that must be allocated
	NumberOfApplicationQueues uint16
	// NumberOfNetworkQueues is the number of network queues allocated
	NumberOfNetworkQueues uint16
	// ApplicationQueue is the queue number of the first application queue
	ApplicationQueue uint16
	// ApplicationQueueSize is the size of the application queue
	ApplicationQueueSize uint32
	// NetworkQueueSize is the size of the network queue
	NetworkQueueSize uint32
}

// Default parameters for the NFQUEUE configuration. Parameters can be
// changed after an isolator has been created and before its started.
// Change in parameters after the isolator is started has no effect
const (
	// DefaultNumberOfQueues  is the default number of queues used in NFQUEUE
	DefaultNumberOfQueues = 4
	// DefaultApplicationQueue represents the queue for application packets
	DefaultApplicationQueue = 0
	// DefaultNetworkQueue represents the queue for the network packets
	DefaultNetworkQueue = 4
	// DefaultQueueSize is the size of the queues
	DefaultQueueSize = 500
	// DefaultMarkValue is the default Mark for packets in the raw chain
	DefaultMarkValue = 0x1111
)
