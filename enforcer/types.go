package enforcer

import (
	"github.com/aporeto-inc/trireme/enforcer/lookup"
	"github.com/aporeto-inc/trireme/policy"
)

// TCPFlowState identifies the constants of the state of a TCP connectioncon
type TCPFlowState int

const (

	// TCPSynSend is the state where the Syn packets has been send, but no response has been received
	TCPSynSend TCPFlowState = iota

	// TCPSynReceived indicates that the syn packet has been received
	TCPSynReceived

	// TCPSynAckSend indicates that the SynAck packet has been send
	TCPSynAckSend

	// TCPSynAckReceived is the state where the SynAck has been received
	TCPSynAckReceived

	// TCPAckSend indicates that the ack packets has been send
	TCPAckSend

	// TCPAckProcessed is the state that the negotiation has been completed
	TCPAckProcessed
)

const (
	// DefaultNetwork is the default IP address used when we don't care about IP addresses
	DefaultNetwork = "0.0.0.0/0"
)

var (
	// TransmitterLabel is the name of the label used to identify the Transmitter Context
	TransmitterLabel = "AporetoContextID"
)

// InterfaceStats for interface
type InterfaceStats struct {
	IncomingPackets     uint32
	OutgoingPackets     uint32
	ProtocolDropPackets uint32
	CreateDropPackets   uint32
}

// PacketStats for interface
type PacketStats struct {
	IncomingPackets        uint32
	OutgoingPackets        uint32
	AuthDropPackets        uint32
	ServicePreDropPackets  uint32
	ServicePostDropPackets uint32
}

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

// PUContext holds data indexed by the docker ID
type PUContext struct {
	ID             string
	ManagementID   string
	Identity       *policy.TagsMap
	Annotations    *policy.TagsMap
	acceptTxtRules *lookup.PolicyDB
	rejectTxtRules *lookup.PolicyDB
	acceptRcvRules *lookup.PolicyDB
	rejectRcvRules *lookup.PolicyDB
	Extension      interface{}
}

// DualHash is a record of app and net hash
type DualHash struct {
	app string
	net string
}
