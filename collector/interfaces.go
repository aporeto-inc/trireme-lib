package collector

import (
	"fmt"

	"go.aporeto.io/trireme-lib/policy"
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
	// InvalidHeader indicates that the TCP header was not there.
	InvalidHeader = "header"
	// InvalidPayload indicates that the TCP payload was not there or bad.
	InvalidPayload = "payload"
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
	// APIPolicyDrop indicates that the request was dropped because of failed API validation.
	APIPolicyDrop = "api"
	// UnableToDial indicates that the proxy cannot dial out the connection
	UnableToDial = "dial"
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
	// SomeClaimsSource provides a string for some claims flow source.
	SomeClaimsSource = "some-claims"
)

// EventCollector is the interface for collecting events.
type EventCollector interface {

	// CollectFlowEvent collect a  flow event.
	CollectFlowEvent(record *FlowRecord)

	// CollectContainerEvent collects a container events
	CollectContainerEvent(record *ContainerRecord)

	// CollectUserEvent  collects a user event
	CollectUserEvent(record *UserRecord)
}

// EndPointType is the type of an endpoint (PU or an external IP address )
type EndPointType byte

const (
	// EndPointTypeExternalIP indicates that the endpoint is an external IP address
	EndPointTypeExternalIP EndPointType = iota
	// EnpointTypePU indicates that the endpoint is a PU.
	EnpointTypePU
	// EndpointTypeClaims indicates that the endpoint is of type claims.
	EndpointTypeClaims
)

func (e *EndPointType) String() string {

	switch *e {
	case EndPointTypeExternalIP:
		return "ext"
	case EnpointTypePU:
		return "pu"
	case EndpointTypeClaims:
		return "claims"
	}

	return "pu" // backward compatibility (CS: 04/24/2018)
}

// EndPoint is a structure that holds all the endpoint information
type EndPoint struct {
	ID         string
	IP         string
	URI        string
	HTTPMethod string
	UserID     string
	Type       EndPointType
	Port       uint16
}

// FlowRecord describes a flow record for statistis
type FlowRecord struct {
	ContextID        string
	Source           *EndPoint
	Destination      *EndPoint
	Tags             *policy.TagStore
	DropReason       string
	PolicyID         string
	ObservedPolicyID string
	ServiceType      policy.ServiceType
	ServiceID        string
	Count            int
	Action           policy.ActionType
	ObservedAction   policy.ActionType
	L4Protocol       uint8
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
	IPAddress policy.ExtendedMap
	Tags      *policy.TagStore
	Event     string
}

// UserRecord reports a new user access. These will be reported
// periodically.
type UserRecord struct {
	ID     string
	Claims []string
}
