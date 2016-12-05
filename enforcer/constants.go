package enforcer

const (
	// TCPAuthenticationOptionBaseLen specifies the length of base TCP Authentication Option packet
	TCPAuthenticationOptionBaseLen = 4
	// TCPAuthenticationOptionAckLen specifies the length of TCP Authentication Option in the ack packet
	TCPAuthenticationOptionAckLen = 20
	// PortNumberLabelString is the label to use for port numbers
	PortNumberLabelString = "@port"
)

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
)
