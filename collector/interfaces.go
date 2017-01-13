package collector

import (
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/policy"
)

const (
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
	// ContainerUpdate indicates a container policy update event
	ContainerUpdate = "update"
	// ContainerFailed indicates an event that a container was stopped because of policy issues
	ContainerFailed = "forcestop"
	// UnknownContainerDelete indicates that policy for an unknwon container was deleted
	UnknownContainerDelete = "unknowncontainer"
	// PolicyValid Normal flow accept
	PolicyValid = "V"
)

// EventCollector is the interface for collecting events.
type EventCollector interface {

	// CollectFlowEvent collects flow events.
	CollectFlowEvent(contextID string, tags *policy.TagsMap, action string, mode string, sourceID string, tcpPacket *packet.Packet)

	// CollectContainerEvent collects container events.
	CollectContainerEvent(contextID string, ip string, tags *policy.TagsMap, event string)
}
