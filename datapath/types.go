package datapath

import "github.com/aporeto-inc/trireme/datapath/lookup"

// FlowState identifies the constants of the state of a connectioncon
type FlowState int

const (

	// SynSend is the state where the Syn packets has been send, but no response has been received
	SynSend FlowState = iota

	//SynReceived indicates that the syn packet has been received
	SynReceived

	//SynAckSend indicates that the SynAck packet has been send
	SynAckSend

	// SynAckReceived is the state where the SynAck has been received
	SynAckReceived

	// AckSend indicates that the ack packets has been send
	AckSend

	// AckProcessed is the state that the negotiation has been completed
	AckProcessed
)

const (
	// TransmitterLabel is the name of the label used to identify the Transmitter Context
	TransmitterLabel = "AporetoContextID"
)

// Service is an interface implemented to stitch into our datapath
type Service interface {
	// PreProcessTCPAppPacket will be called for application packets and return value of false means drop packet.
	PreProcessTCPAppPacket(pkt interface{}) bool
	// PostProcessTCPAppPacket will be called for application packets and return value of false means drop packet.
	PostProcessTCPAppPacket(pkt interface{}, action interface{}) bool
	// PreProcessTCPNetPacket will be called for network packets and return value of false means drop packet
	PreProcessTCPNetPacket(pkt interface{}) bool
	// PostProcessTCPNetPacket will be called for network packets and return value of false means drop packet
	PostProcessTCPNetPacket(pkt interface{}, action interface{}) bool
}

// PacketStats for interface
type PacketStats struct {
	IncomingPackets uint32
	OutgoingPackets uint32

	CreateDropPackets      uint32
	AuthDropPackets        uint32
	ServicePreDropPackets  uint32
	ServicePostDropPackets uint32
}

// FilterQueueConfig captures all the configuration parameters of the NFQUEUEs
type FilterQueueConfig struct {
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

// PUContext holds data indexed by the docker ID
type PUContext struct {
	ID        string
	Tags      map[string]string
	rules     *lookup.PolicyDB
	Extension interface{}
}
