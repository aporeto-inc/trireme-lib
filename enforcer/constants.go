package enforcer

const (
	// TCPAuthenticationOptionBaseLen specifies the length of base TCP Authentication Option packet
	TCPAuthenticationOptionBaseLen = 4
	// TCPAuthenticationOptionAckLen specifies the length of TCP Authentication Option in the ack packet
	TCPAuthenticationOptionAckLen = 20
	// PortNumberLabelString is the label to use for port numbers
	PortNumberLabelString = "$sys:port"
	// TransmitterLabel is the name of the label used to identify the Transmitter Context
	TransmitterLabel = "AporetoContextID"
	// DefaultNetwork to be used
	DefaultNetwork = "0.0.0.0/0"
)
