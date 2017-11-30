package eventinfo

import (
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/policy"
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
