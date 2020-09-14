package fqconfig

// FilterQueue captures all the configuration parameters of the NFQUEUEs and Iptables configuration.
type FilterQueue struct {
	// MarkValue is the default mark to set in packets in the RAW chain
	MarkValue int
	// NetworkQueue is the queue number of the base queue for network packets
	NetworkQueue uint16
	// NumberOfApplicationQueues is the number of queues that must be allocated
	NumberOfQueues uint16
	// ApplicationQueue is the queue number of the first application queue
	ApplicationQueue uint16
	// ApplicationQueueSize is the size of the application queue
	ApplicationQueueSize uint32
	// NetworkQueueSize is the size of the network queue
	NetworkQueueSize uint32
	// DNSServerAddress
	DNSServerAddress []string
}

// NewFilterQueueWithDefaults return a default filter queue config
func NewFilterQueueWithDefaults() *FilterQueue {
	return NewFilterQueue(
		DefaultQueueSeperation,
		DefaultMarkValue,
		DefaultQueueStart,
		DefaultNumberOfQueues,
		DefaultNumberOfQueues,
		DefaultQueueSize,
		DefaultQueueSize,
		nil,
	)
}

// NewFilterQueue returns an instance of FilterQueue
func NewFilterQueue(queueSeparation bool, MarkValue int, QueueStart, NumberOfNetworkQueues, NumberOfApplicationQueues uint16, networkQueueSize, applicationQueueSize uint32, dnsServerAddress []string) *FilterQueue {

	fq := &FilterQueue{
		MarkValue:        MarkValue,
		NumberOfQueues:   1,
		DNSServerAddress: dnsServerAddress,
	}

	fq.ApplicationQueue = 0
	fq.NetworkQueue = 0

	return fq
}

// GetMarkValue returns a mark value to be used by iptables action
func (f *FilterQueue) GetMarkValue() int {
	return f.MarkValue
}

// GetNetworkQueueStart returns start of network queues to be used by iptables action
func (f *FilterQueue) GetNumQueues() uint16 {
	return f.NumberOfQueues
}

// Default parameters for the NFQUEUE configuration. Parameters can be
// changed after an isolator has been created and before its started.
// Change in parameters after the isolator is started has no effect
const (
	// DefaultQueueSeperation specifies if we should use separate queues for packet types
	DefaultQueueSeperation = true
	// DefaultNumberOfQueues  is the default number of queues used in NFQUEUE
	DefaultNumberOfQueues = 4
	// DefaultQueueStart represents the queue number to start
	DefaultQueueStart = 0
	// DefaultQueueSize is the size of the queues
	DefaultQueueSize = 500
	// DefaultMarkValue is the default Mark for packets in the raw chain
	DefaultMarkValue = 0x1111
)
