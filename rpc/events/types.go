package events

import (
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/policy"
)

const (
	// EventInfoCurrentVersion specifies the current version in use.
	EventInfoCurrentVersion = 1
)

// EventInfo is a generic structure that defines all the information related to a PU event.
// EventInfo should be used as a normalized struct container that
type EventInfo struct {

	// Version holds the version for compatability purposes.
	Version int

	// EventType refers to one of the standard events that Trireme handles.
	EventType Event

	// PUType is the the type of the PU
	PUType constants.PUType

	// The PUID is a unique value for the Processing Unit. Ideally this should be the UUID.
	PUID string

	// The Name is a user-friendly name for the Processing Unit.
	Name string

	// Tags represents the set of MetadataTags associated with this PUID.
	Tags []string

	// The PID is the PID on the system where this Processing Unit is running.
	PID string

	// The path for the Network Namespace.
	NS string

	// Cgroup is the path to the cgroup - used for deletes
	Cgroup string

	// IPs is a map of all the IPs that fully belong to this processing Unit.
	IPs map[string]string

	// Services is a list of services of interest - for host control
	Services []policy.Service

	// HostService indicates that the request is for the root namespace
	HostService bool

	// NetworkOnlyTraffic indicates that traffic towards the applications must be controlled.
	NetworkOnlyTraffic bool

	// Root indicates that this request is coming from a roor user. Its overwritten by the enforcer
	Root bool
}

// EventMetadataExtractor is a function used to extract a *policy.PURuntime from a given
// EventInfo.
type EventMetadataExtractor func(*EventInfo) (*policy.PURuntime, error)

// Event represents the event picked up by the monitor.
type Event string

const (
	// EventStart is the event generated when a PU starts.
	EventStart Event = "start"

	// EventStop is the event generated when a PU stops/dies.
	EventStop Event = "stop"

	// EventCreate is the event generated when a PU gets created.
	EventCreate Event = "create"

	// EventDestroy is the event generated when a PU is definitely removed.
	EventDestroy Event = "destroy"

	// EventPause is the event generated when a PU is set to pause.
	EventPause Event = "pause"

	// EventUnpause is the event generated when a PU is unpaused.
	EventUnpause Event = "unpause"

	// EventResync instructs the processors to resync
	EventResync Event = "resync"
)

// EventResponse encapsulate the error response if any.
type EventResponse struct {
	Error string
}

// A EventHandler is type of event handler functions.
type EventHandler func(*EventInfo) error

// A State describes the state of the PU.
type State int

const (
	// StateStarted is the state of a started PU.
	StateStarted State = iota + 1

	// StateStopped is the state of stopped PU.
	StateStopped

	// StatePaused is the state of a paused PU.
	StatePaused

	// StateDestroyed is the state of destroyed PU.
	StateDestroyed

	// StateUnknwown is the state of PU in an unknown state.
	StateUnknwown
)
