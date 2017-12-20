package collector

import (
	"fmt"

	"github.com/aporeto-inc/trireme-lib/policy"
)

// Flow event description
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
)

// Container event description
const (
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
	// ContainerDeleteUnknown indicates that policy for an unknown  container was deleted
	ContainerDeleteUnknown = "unknowncontainer"
)

const (
	// PolicyValid Normal flow accept
	PolicyValid = "V"
	// DefaultEndPoint  provides a string for unknown container sources
	DefaultEndPoint = "default"
)

// EventCollector is the interface for collecting events.
type EventCollector interface {

	// CollectFlowEvent collect a  flow event.
	CollectFlowEvent(record *FlowRecord)

	// CollectContainerEvent collects a container events
	CollectContainerEvent(record *ContainerRecord)
}

// EndPointType is the type of an endpoint (PU or an external IP address )
type EndPointType byte

const (
	// Address indicates that the endpoint is an external IP address
	Address EndPointType = iota
	// PU indicates that the endpoint is a PU
	PU
)

func (e *EndPointType) String() string {
	if *e == Address {
		return "ext"
	}
	return "pu"
}

// EndPoint is a structure that holds all the endpoint information
type EndPoint struct {
	ID   string
	IP   string
	Port uint16
	Type EndPointType
}

// FlowRecord describes a flow record for statistis
type FlowRecord struct {
	ContextID        string
	Count            int
	Source           *EndPoint
	Destination      *EndPoint
	Tags             *policy.TagStore
	Action           policy.ActionType
	ObservedAction   policy.ActionType
	DropReason       string
	PolicyID         string
	ObservedPolicyID string
}

func (f *FlowRecord) String() string {
	return fmt.Sprintf("<flowrecord contextID:%s count:%d sourceID:%s destinationID:%s sourceIP: %s destinationIP:%s destinationPort:%d action:%s mode:%s>",
		f.ContextID,
		f.Count,
		f.Source.ID,
		f.Destination.ID,
		f.Source.IP,
		f.Destination.IP,
		f.Destination.Port,
		f.Action.String(),
		f.DropReason,
	)
}

// ContainerRecord is a statistics record for a container
type ContainerRecord struct {
	ContextID string
	IPAddress string
	Tags      *policy.TagStore
	Event     string
}
