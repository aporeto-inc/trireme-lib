package eventlog

import "github.com/aporeto-inc/trireme/datapath/packet"

var (
	// FlowReject indicates that a flow was rejected
	FlowReject = "reject"
	// FlowAccept logs that a flow is accepted
	FlowAccept = "accept"
	// MissingToken indicates that the token was missing
	MissingToken = "missingtoken"
	// InvalidToken indicates that the token was invalid
	InvalidToken = "token"
	// InvalidFormat indicates that the packet metadata were not correct
	InvalidFormat = "format"
	// InvalidContext indicates that there was no context in the metadata
	InvalidContext = "context"
	// InvalidState indicates that a packet was received without proper state information
	InvalidState = "state"
	// InvalidNonse indicates that the nonse check failed
	InvalidNonse = "nonse"
	// PolicyDrop indicates that the flow is rejected because of the policy decision
	PolicyDrop = "policy"
	// ContainerStart indicates a container start event
	ContainerStart = "start"
	// ContainerStop indicates a container stop event
	ContainerStop = "stop"
	// ContainerCreate indicates a container create event
	ContainerCreate = "create"
	// ContainerDelete indicates a container delete event
	ContainerDelete = "delete"
	// ContainerFailed indicates an event that a container was stopped because of policy issues
	ContainerFailed = "forcestop"
	// UnknownContainerDelete indicates that policy for an unknwon container was deleted
	UnknownContainerDelete = "unknowncontainer"
	// PolicyValid Normal flow accept
	PolicyValid = "V"
)

// EventLogger is the interface to the logging functions
type EventLogger interface {
	FlowEvent(contextID string, labels map[string]string, action string, mode string, sourceID string, tcpPacket *packet.Packet)
	ContainerEvent(contextID string, ip string, labels map[string]string, event string)
}

// DefaultLogger implements a default logging infrastructure to syslog
type DefaultLogger struct{}

// FlowEvent  logs flows
func (d *DefaultLogger) FlowEvent(contextID string, labels map[string]string, action string, mode string, sourceID string, tcpPacket *packet.Packet) {
	return
}

// ContainerEvent logs container events
func (d *DefaultLogger) ContainerEvent(contextID string, ip string, labels map[string]string, event string) {
	return
}
