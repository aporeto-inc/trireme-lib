package collector

import "github.com/aporeto-inc/trireme/policy"

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
	// InvalidConnection indicates that there was no connection found
	InvalidConnection = "connection"
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
	// ContainerIgnored indicates that the container will be ignored by Trireme
	ContainerIgnored = "ignore"
	// UnknownContainerDelete indicates that policy for an unknown  container was deleted
	UnknownContainerDelete = "unknowncontainer"
	// PolicyValid Normal flow accept
	PolicyValid = "V"
)

// EventCollector is the interface for collecting events.
type EventCollector interface {

	// CollectFlowEvent collect a  flow event.
	CollectFlowEvent(record *FlowRecord)

	// CollectContainerEvent collects a container events
	CollectContainerEvent(record *ContainerRecord)
}

// FlowRecord describes a flow record for statistis
type FlowRecord struct {
	ContextID       string
	Count           int
	SourceID        string
	DestinationID   string
	SourceIP        string
	DestinationIP   string
	DestinationPort uint16
	Tags            *policy.TagsMap
	Action          string
	Mode            string
}

// ContainerRecord is a statistics record for a container
type ContainerRecord struct {
	ContextID string
	IPAddress string
	Tags      *policy.TagsMap
	Event     string
}
