package rpcmonitor

import "github.com/aporeto-inc/trireme/monitor"

const (

	// Rpcaddress is the default Linux socket for the RPC monitor
	Rpcaddress = "/var/run/trireme/trireme.sock"
)

// EventInfo is a generic structure that defines all the information related to a PU event.
// EventInfo should be used as a normalized struct container that
type EventInfo struct {

	// EventType refers to one of the standard events that Trireme handles.
	EventType monitor.Event

	// The PUID is a unique value for the Processing Unit. Ideally this should be the UUID.
	PUID string

	// The Name is a user-friendly name for the Processing Unit.
	Name string

	// Tags represents the set of MetadataTags associated with this PUID.
	Tags map[string]string

	// The PID is the PID on the system where this Processing Unit is running.
	PID string

	// IPs is a map of all the IPs that fully belong to this processing Unit.
	IPs map[string]string
}

// RPCResponse encapsulate the error response if any.
type RPCResponse struct {
	Error string
}
