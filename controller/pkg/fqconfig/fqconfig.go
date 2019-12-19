package fqconfig

import "strconv"

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
		fq.ApplicationQueuesSynStr = strconv.Itoa(int(fq.ApplicationQueue)) + ":" + strconv.Itoa(int(fq.ApplicationQueue+NumberOfApplicationQueues-1))
		fq.ApplicationQueuesAckStr = strconv.Itoa(int(fq.ApplicationQueue+1*NumberOfApplicationQueues)) + ":" + strconv.Itoa(int(fq.ApplicationQueue+2*NumberOfApplicationQueues-1))
		fq.ApplicationQueuesSynAckStr = strconv.Itoa(int(fq.ApplicationQueue+2*NumberOfApplicationQueues)) + ":" + strconv.Itoa(int(fq.ApplicationQueue+3*NumberOfApplicationQueues-1))
		fq.ApplicationQueuesSvcStr = strconv.Itoa(int(fq.ApplicationQueue+3*NumberOfApplicationQueues)) + ":" + strconv.Itoa(int(fq.ApplicationQueue+4*NumberOfApplicationQueues-1))
		fq.NumberOfApplicationQueues = NumberOfApplicationQueues * 4

		fq.NetworkQueue = QueueStart + fq.NumberOfApplicationQueues
		fq.NetworkQueuesSynStr = strconv.Itoa(int(fq.NetworkQueue)) + ":" + strconv.Itoa(int(fq.NetworkQueue+NumberOfNetworkQueues-1))
		fq.NetworkQueuesAckStr = strconv.Itoa(int(fq.NetworkQueue+1*NumberOfNetworkQueues)) + ":" + strconv.Itoa(int(fq.NetworkQueue+2*NumberOfNetworkQueues-1))
		fq.NetworkQueuesSynAckStr = strconv.Itoa(int(fq.NetworkQueue+2*NumberOfNetworkQueues)) + ":" + strconv.Itoa(int(fq.NetworkQueue+3*NumberOfNetworkQueues-1))
		fq.NetworkQueuesSvcStr = strconv.Itoa(int(fq.NetworkQueue+3*NumberOfNetworkQueues)) + ":" + strconv.Itoa(int(fq.NetworkQueue+4*NumberOfNetworkQueues-1))
		fq.NumberOfNetworkQueues = NumberOfNetworkQueues * 4
	} else {

		fq.ApplicationQueue = QueueStart
		fq.ApplicationQueuesSynStr = strconv.Itoa(int(fq.ApplicationQueue)) + ":" + strconv.Itoa(int(fq.ApplicationQueue+NumberOfApplicationQueues-1))
		fq.ApplicationQueuesAckStr = fq.ApplicationQueuesSynStr
		fq.ApplicationQueuesSvcStr = fq.ApplicationQueuesSynStr
		fq.ApplicationQueuesSynAckStr = fq.ApplicationQueuesSynStr
		fq.NumberOfApplicationQueues = NumberOfApplicationQueues

		fq.NetworkQueue = QueueStart + fq.NumberOfApplicationQueues
		fq.NetworkQueuesSynStr = strconv.Itoa(int(fq.NetworkQueue)) + ":" + strconv.Itoa(int(fq.NetworkQueue+NumberOfNetworkQueues-1))
		fq.NetworkQueuesAckStr = fq.NetworkQueuesSynStr
		fq.NetworkQueuesSynAckStr = fq.NetworkQueuesSynStr
		fq.NetworkQueuesSvcStr = fq.NetworkQueuesSynStr
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

// GetNetworkQueueSynStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetNetworkQueueSynStr() string {
	return f.NetworkQueuesSynStr
}

// GetNetworkQueueAckStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetNetworkQueueAckStr() string {
	return f.NetworkQueuesAckStr
}

// GetNetworkQueueSynAckStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetNetworkQueueSynAckStr() string {
	return f.NetworkQueuesSynAckStr
}

// GetNetworkQueueSvcStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetNetworkQueueSvcStr() string {
	return f.NetworkQueuesSvcStr
}

// GetApplicationQueueSynStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetApplicationQueueSynStr() string {
	return f.ApplicationQueuesSynStr
}

// GetApplicationQueueAckStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetApplicationQueueAckStr() string {
	return f.ApplicationQueuesAckStr
}

// GetApplicationQueueSynAckStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetApplicationQueueSynAckStr() string {

	return f.ApplicationQueuesSynAckStr
}

// GetApplicationQueueSvcStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetApplicationQueueSvcStr() string {

	return f.ApplicationQueuesSvcStr
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
