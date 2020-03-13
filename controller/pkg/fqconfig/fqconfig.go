package fqconfig

// FilterQueue captures all the configuration parameters of the NFQUEUEs and Iptables configuration.
type FilterQueue struct {
	// QueueSeparation specifies if we should use separate queues per packet type
	QueueSeparation bool
	// MarkValue is the default mark to set in packets in the RAW chain
	MarkValue int
	// NetworkQueue is the queue number of the base queue for network packets
	NetworkQueue uint16
	// NumberOfApplicationQueues is the number of queues that must be allocated
	NumberOfApplicationQueues uint16
	// numberOfNetworkQueues is the number of network queues allocated
	NumberOfNetworkQueues uint16
	// ApplicationQueue is the queue number of the first application queue
	ApplicationQueue uint16
	// ApplicationQueueSize is the size of the application queue
	ApplicationQueueSize uint32
	// NetworkQueueSize is the size of the network queue
	NetworkQueueSize uint32
	// NetworkSynQueues the range of network queues for syn packets
	NetworkSynQueues []uint32
	// NetworkSynAckQueues the range of network queues for syn ack packets
	NetworkSynAckQueues []uint32
	// NetworkAckQueues the range of network queues for ack packets
	NetworkAckQueues []uint32
	// NetworkQueuesSvc the range of network queus for services
	NetworkQueuesSvc []uint32
	// ApplicationSynQueues is the range of application queues for syn packets
	ApplicationSynQueues []uint32
	// ApplicationAckQueues is the range of application queues for application ack packets
	ApplicationAckQueues []uint32
	// ApplicationQueuesSvc is the range of queues  for application service packets
	ApplicationQueuesSvc []uint32
	// ApplicationSynAckQueues is the range of queues for application synack packets
	ApplicationSynAckQueues []uint32

	// NetworkQueuesSynStr is the queue string for network syn
	NetworkQueuesSynStr string
	// NetworkQueuesAckStr is the queue string for network ack
	NetworkQueuesAckStr string
	// NetworkQueuesSynAckStr is the queue string for network synack packets
	NetworkQueuesSynAckStr string
	// NetworkQueuesSvcStr is the queue string for services
	NetworkQueuesSvcStr string
	// ApplicationQueuesSynStr is the queue string for application syn packets
	ApplicationQueuesSynStr string
	// ApplicationQueuesAckStr is the queue string for application ack packets
	ApplicationQueuesAckStr string
	// ApplicationQueuesSvcStr is the queue string for application service packets
	ApplicationQueuesSvcStr string
	// ApplicationQueuesSynAckStr is the queue string for application synack packets
	ApplicationQueuesSynAckStr string
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

func createQueueSlice(startQueue uint16, numQueues uint16) []uint32 {
	queues := make([]uint32, int(numQueues))
	for i := startQueue; i < (startQueue + numQueues); i++ {
		queues[i-startQueue] = uint32(i)
	}
	return queues
}

// NewFilterQueue returns an instance of FilterQueue
func NewFilterQueue(queueSeparation bool, MarkValue int, QueueStart, NumberOfNetworkQueues, NumberOfApplicationQueues uint16, NetworkQueueSize, ApplicationQueueSize uint32, dnsServerAddress []string) *FilterQueue {

	fq := &FilterQueue{
		QueueSeparation:      queueSeparation,
		MarkValue:            MarkValue,
		NetworkQueueSize:     NetworkQueueSize,
		ApplicationQueueSize: ApplicationQueueSize,
		DNSServerAddress:     dnsServerAddress,
	}

	if queueSeparation {

		fq.ApplicationQueue = QueueStart
		fq.ApplicationSynQueues = createQueueSlice(fq.ApplicationQueue, NumberOfApplicationQueues)
		fq.ApplicationAckQueues = createQueueSlice(fq.ApplicationQueue+1*NumberOfApplicationQueues, NumberOfApplicationQueues)
		fq.ApplicationSynAckQueues = createQueueSlice((fq.ApplicationQueue + 2*NumberOfApplicationQueues), NumberOfApplicationQueues)
		fq.ApplicationQueuesSvc = createQueueSlice(fq.ApplicationQueue+3*NumberOfApplicationQueues, NumberOfApplicationQueues)
		fq.NumberOfApplicationQueues = NumberOfApplicationQueues * 4

		fq.NetworkQueue = QueueStart + fq.NumberOfApplicationQueues
		fq.NetworkSynQueues = createQueueSlice(fq.NetworkQueue, NumberOfNetworkQueues)
		fq.NetworkAckQueues = createQueueSlice(fq.NetworkQueue+1*NumberOfNetworkQueues, NumberOfNetworkQueues)
		fq.NetworkSynAckQueues = createQueueSlice(fq.NetworkQueue+2*NumberOfNetworkQueues, NumberOfNetworkQueues)
		fq.NetworkQueuesSvc = createQueueSlice(fq.NetworkQueue+3*NumberOfNetworkQueues, NumberOfNetworkQueues)
		fq.NumberOfNetworkQueues = NumberOfNetworkQueues * 4
	} else {

		fq.ApplicationQueue = QueueStart
		fq.ApplicationSynQueues = createQueueSlice(fq.ApplicationQueue, NumberOfApplicationQueues)
		fq.ApplicationSynAckQueues = fq.ApplicationSynQueues
		fq.ApplicationAckQueues = fq.ApplicationSynQueues
		fq.ApplicationQueuesSvc = fq.ApplicationSynQueues
		fq.NumberOfApplicationQueues = NumberOfApplicationQueues

		fq.NetworkQueue = QueueStart + fq.NumberOfApplicationQueues
		fq.NetworkSynQueues = createQueueSlice(fq.NetworkQueue, NumberOfNetworkQueues)
		fq.NetworkAckQueues = fq.NetworkSynQueues
		fq.NetworkSynAckQueues = fq.NetworkSynQueues
		fq.NetworkQueuesSvc = fq.NetworkSynQueues
		fq.NumberOfNetworkQueues = NumberOfNetworkQueues
	}

	return fq
}

// GetMarkValue returns a mark value to be used by iptables action
func (f *FilterQueue) GetMarkValue() int {
	return f.MarkValue
}

// GetNetworkQueueStart returns start of network queues to be used by iptables action
func (f *FilterQueue) GetNetworkQueueStart() uint16 {
	return f.NetworkQueue
}

// GetNumNetworkQueues returns number of network queues to be used by iptables action
func (f *FilterQueue) GetNumNetworkQueues() uint16 {
	return f.NumberOfNetworkQueues
}

// GetNetworkQueueSize returns size of network queues to be used by iptables action
func (f *FilterQueue) GetNetworkQueueSize() uint32 {
	return f.NetworkQueueSize
}

// GetApplicationQueueStart returns start of application queues to be used by iptables action
func (f *FilterQueue) GetApplicationQueueStart() uint16 {
	return f.ApplicationQueue
}

// GetNumApplicationQueues returns number of application queues to be used by iptables action
func (f *FilterQueue) GetNumApplicationQueues() uint16 {
	return f.NumberOfApplicationQueues
}

// GetApplicationQueueSize returns size of application queues to be used by iptables action
func (f *FilterQueue) GetApplicationQueueSize() uint32 {
	return f.ApplicationQueueSize
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
