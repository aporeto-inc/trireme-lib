package rpcmonitor

import (
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor"
)

const (

	// DefaultRPCAddress is the default Linux socket for the RPC monitor
	DefaultRPCAddress = "/var/run/trireme.sock"
)

// EventInfo is a generic structure that defines all the information related to a PU event.
// EventInfo should be used as a normalized struct container that
type EventInfo struct {

	// EventType refers to one of the standard events that Trireme handles.
	EventType monitor.Event

	// PUType is the the type of the PU
	PUType constants.PUType

	// The PUID is a unique value for the Processing Unit. Ideally this should be the UUID.
	PUID string

	// The Name is a user-friendly name for the Processing Unit.
	Name string

	// Tags represents the set of MetadataTags associated with this PUID.
	Tags map[string]string

	// The PID is the PID on the system where this Processing Unit is running.
	PID string

	// The path for the Network Namespace.
	NS string

	// IPs is a map of all the IPs that fully belong to this processing Unit.
	IPs map[string]string
}

// RPCResponse encapsulate the error response if any.
type RPCResponse struct {
	Error string
}

// MonitorProcessor is a generic interface that processes monitor events using
// a normalized event structure.
type MonitorProcessor interface {

	// Start processes PU start events
	Start(eventInfo *EventInfo) error

	// Event processes PU stop events
	Stop(eventInfo *EventInfo) error

	// Create process a PU create event
	Create(eventInfo *EventInfo) error

	// Event process a PU destroy event
	Destroy(eventInfo *EventInfo) error

	// Event processes a pause event
	Pause(eventInfo *EventInfo) error
}
