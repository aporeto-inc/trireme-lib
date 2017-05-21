package fqconfig

import "strconv"

// FilterQueue captures all the configuration parameters of the NFQUEUEs
type FilterQueue struct {
	// queueSeparation specifies if we should use separate queues per packet type
	queueSeparation bool
	// MarkValue is the default mark to set in packets in the RAW chain
	markValue int
	// Network Queue is the queue number of the base queue for network packets
	networkQueue uint16
	// NumberOfApplicationQueues is the number of queues that must be allocated
	numberOfApplicationQueues uint16
	// NumberOfNetworkQueues is the number of network queues allocated
	numberOfNetworkQueues uint16
	// ApplicationQueue is the queue number of the first application queue
	applicationQueue uint16
	// ApplicationQueueSize is the size of the application queue
	applicationQueueSize uint32
	// NetworkQueueSize is the size of the network queue
	networkQueueSize uint32

	// Strings for programming NFQ
	networkQueuesStr           string
	networkQueuesSynStr        string
	networkQueuesSynAckStr     string
	networkQueuesAckStr        string
	networkQueuesSvcStr        string
	applicationQueuesStr       string
	applicationQueuesSynStr    string
	applicationQueuesSynAckStr string
	applicationQueuesAckStr    string
	applicationQueuesSvcStr    string
}

// FilterQueueImpl is the interface for filter queue configs
type FilterQueueImpl interface {

	// GetMarkValue returns a mark value to be used by iptables action
	GetMarkValue() int

	// GetNetworkQueueStart returns start of network queues to be used by iptables action
	GetNetworkQueueStart() uint16

	// GetNumNetworkQueues returns number of network queues to be used by iptables action
	GetNumNetworkQueues() uint16

	// GetNetworkQueueSize returns size of network queues to be used by iptables action
	GetNetworkQueueSize() uint32

	// GetApplicationQueueStart returns start of application queues to be used by iptables action
	GetApplicationQueueStart() uint16

	// GetNumApplicationQueues returns number of application queues to be used by iptables action
	GetNumApplicationQueues() uint16

	// GetApplicationQueueSize returns size of application queues to be used by iptables action
	GetApplicationQueueSize() uint32
	// GetNetworkQueueStr returns a queue id string to be used by iptables action
	GetNetworkQueueStr() string

	// GetNetworkQueueSynStr returns a queue id string to be used by iptables action
	GetNetworkQueueSynStr() string

	// GetNetworkQueueSynAckStr returns a queue id string to be used by iptables action
	GetNetworkQueueSynAckStr() string

	// GetNetworkQueueAckStr returns a queue id string to be used by iptables action
	GetNetworkQueueAckStr() string

	// GetNetworkQueueSvcStr returns a queue id string to be used by iptables action
	GetNetworkQueueSvcStr() string

	// GetApplicationQueueStr returns a queue id string to be used by iptables action
	GetApplicationQueueStr() string

	// GetApplicationQueueSynStr returns a queue id string to be used by iptables action
	GetApplicationQueueSynStr() string

	// GetApplicationQueueSynAckStr returns a queue id string to be used by iptables action
	GetApplicationQueueSynAckStr() string

	// GetApplicationQueueAckStr returns a queue id string to be used by iptables action
	GetApplicationQueueAckStr() string

	// GetApplicationQueueSvcStr returns a queue id string to be used by iptables action
	GetApplicationQueueSvcStr() string
}

// NewFilterQueueWithDefaults return a default filter queue config
func NewFilterQueueWithDefaults() FilterQueueImpl {
	return NewFilterQueue(
		DefaultQueueSeperation,
		DefaultQueueStart,
		DefaultQueueSize,
		DefaultNumberOfQueues,
		DefaultQueueSize,
		DefaultNumberOfQueues,
		DefaultMarkValue,
	)
}

// NewFilterQueue returns an instance of FilterQueue
func NewFilterQueue(queueSeparation bool, MarkValue int, QueueStart, NumberOfNetworkQueues, NumberOfApplicationQueues uint16, NetworkQueueSize, ApplicationQueueSize uint32) FilterQueueImpl {

	fq := &FilterQueue{
		queueSeparation:           queueSeparation,
		markValue:                 MarkValue,
		networkQueue:              QueueStart + NumberOfApplicationQueues,
		numberOfNetworkQueues:     NumberOfNetworkQueues,
		networkQueueSize:          NetworkQueueSize,
		applicationQueue:          QueueStart,
		numberOfApplicationQueues: NumberOfApplicationQueues,
		applicationQueueSize:      ApplicationQueueSize,
	}

	if queueSeparation {
		// We use 4 times the number of queues if queue separation is requested
		fq.applicationQueue = QueueStart
		fq.numberOfApplicationQueues = fq.numberOfApplicationQueues * 4
		fq.networkQueue = QueueStart + fq.numberOfApplicationQueues
		fq.numberOfNetworkQueues = fq.numberOfNetworkQueues * 4

		fq.networkQueuesStr = strconv.Itoa(int(fq.networkQueue)) + ":" + strconv.Itoa(int(fq.networkQueue+fq.numberOfNetworkQueues-1))
		fq.networkQueuesSynStr = strconv.Itoa(int(fq.networkQueue)) + ":" + strconv.Itoa(int(fq.networkQueue+fq.numberOfNetworkQueues-1))
		fq.networkQueuesSynAckStr = strconv.Itoa(int(fq.networkQueue+fq.numberOfNetworkQueues)) + ":" + strconv.Itoa(int(fq.networkQueue+2*fq.numberOfNetworkQueues-1))
		fq.networkQueuesAckStr = strconv.Itoa(int(fq.networkQueue+2*fq.numberOfNetworkQueues)) + ":" + strconv.Itoa(int(fq.networkQueue+3*fq.numberOfNetworkQueues-1))
		fq.networkQueuesSvcStr = strconv.Itoa(int(fq.networkQueue+3*fq.numberOfNetworkQueues)) + ":" + strconv.Itoa(int(fq.networkQueue+4*fq.numberOfNetworkQueues-1))

		fq.applicationQueuesStr = strconv.Itoa(int(fq.applicationQueue)) + ":" + strconv.Itoa(int(fq.applicationQueue+fq.numberOfApplicationQueues-1))
		fq.applicationQueuesSynStr = strconv.Itoa(int(fq.applicationQueue)) + ":" + strconv.Itoa(int(fq.applicationQueue+fq.numberOfApplicationQueues-1))
		fq.applicationQueuesSynAckStr = strconv.Itoa(int(fq.applicationQueue+fq.numberOfApplicationQueues)) + ":" + strconv.Itoa(int(fq.applicationQueue+2*fq.numberOfApplicationQueues-1))
		fq.applicationQueuesAckStr = strconv.Itoa(int(fq.applicationQueue+2*fq.numberOfApplicationQueues)) + ":" + strconv.Itoa(int(fq.applicationQueue+3*fq.numberOfApplicationQueues-1))
		fq.applicationQueuesSvcStr = strconv.Itoa(int(fq.applicationQueue+3*fq.numberOfApplicationQueues)) + ":" + strconv.Itoa(int(fq.applicationQueue+4*fq.numberOfApplicationQueues-1))
	} else {

		fq.networkQueuesStr = strconv.Itoa(int(fq.networkQueue)) + ":" + strconv.Itoa(int(fq.networkQueue+fq.numberOfNetworkQueues-1))
		fq.networkQueuesSynStr = fq.networkQueuesStr
		fq.networkQueuesSynAckStr = fq.networkQueuesStr
		fq.networkQueuesAckStr = fq.networkQueuesStr
		fq.networkQueuesSvcStr = fq.networkQueuesStr

		fq.applicationQueuesStr = strconv.Itoa(int(fq.applicationQueue)) + ":" + strconv.Itoa(int(fq.applicationQueue+fq.numberOfApplicationQueues-1))
		fq.applicationQueuesSynStr = fq.applicationQueuesStr
		fq.applicationQueuesSynAckStr = fq.applicationQueuesStr
		fq.applicationQueuesAckStr = fq.applicationQueuesStr
		fq.applicationQueuesSvcStr = fq.applicationQueuesStr
	}
	return fq
}

// GetMarkValue returns a mark value to be used by iptables action
func (f *FilterQueue) GetMarkValue() int {
	return f.markValue
}

// GetNetworkQueueStart returns start of network queues to be used by iptables action
func (f *FilterQueue) GetNetworkQueueStart() uint16 {
	return f.networkQueue
}

// GetNumNetworkQueues returns number of network queues to be used by iptables action
func (f *FilterQueue) GetNumNetworkQueues() uint16 {
	return f.numberOfNetworkQueues
}

// GetNetworkQueueSize returns size of network queues to be used by iptables action
func (f *FilterQueue) GetNetworkQueueSize() uint32 {
	return f.networkQueueSize
}

// GetApplicationQueueStart returns start of application queues to be used by iptables action
func (f *FilterQueue) GetApplicationQueueStart() uint16 {
	return f.applicationQueue
}

// GetNumApplicationQueues returns number of application queues to be used by iptables action
func (f *FilterQueue) GetNumApplicationQueues() uint16 {
	return f.numberOfApplicationQueues
}

// GetApplicationQueueSize returns size of application queues to be used by iptables action
func (f *FilterQueue) GetApplicationQueueSize() uint32 {
	return f.applicationQueueSize
}

// GetNetworkQueueStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetNetworkQueueStr() string {
	return f.networkQueuesStr
}

// GetNetworkQueueSynStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetNetworkQueueSynStr() string {
	return f.networkQueuesSynStr
}

// GetNetworkQueueSynAckStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetNetworkQueueSynAckStr() string {
	return f.networkQueuesSynAckStr
}

// GetNetworkQueueAckStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetNetworkQueueAckStr() string {
	return f.networkQueuesAckStr
}

// GetNetworkQueueSvcStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetNetworkQueueSvcStr() string {
	return f.networkQueuesSvcStr
}

// GetApplicationQueueStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetApplicationQueueStr() string {
	return f.applicationQueuesStr
}

// GetApplicationQueueSynStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetApplicationQueueSynStr() string {
	return f.applicationQueuesSynStr
}

// GetApplicationQueueSynAckStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetApplicationQueueSynAckStr() string {
	return f.applicationQueuesSynAckStr
}

// GetApplicationQueueAckStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetApplicationQueueAckStr() string {
	return f.applicationQueuesAckStr
}

// GetApplicationQueueSvcStr returns a queue id string to be used by iptables action
func (f *FilterQueue) GetApplicationQueueSvcStr() string {
	return f.applicationQueuesSvcStr
}

// Default parameters for the NFQUEUE configuration. Parameters can be
// changed after an isolator has been created and before its started.
// Change in parameters after the isolator is started has no effect
const (
	// DefaultQueueSeperation specifies if we should use separate queues for packet types
	DefaultQueueSeperation = false
	// DefaultNumberOfQueues  is the default number of queues used in NFQUEUE
	DefaultNumberOfQueues = 4
	// DefaultQueueStart represents the queue number to start
	DefaultQueueStart = 0
	// DefaultQueueSize is the size of the queues
	DefaultQueueSize = 500
	// DefaultMarkValue is the default Mark for packets in the raw chain
	DefaultMarkValue = 0x1111
)
