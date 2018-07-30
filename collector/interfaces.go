package collector

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
	// APIPolicyDrop indicates that the request was dropped because of failed API validation.
	APIPolicyDrop = "api"
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
