package monitor

import (
	"github.com/aporeto-inc/trireme/policy"
	"github.com/docker/docker/api/types/events"
)

// DockerEvent is the type of various docker events.
type DockerEvent string

const (
	// DockerEventStart represents the Docker "start" event.
	DockerEventStart DockerEvent = "start"

	// DockerEventDie represents the Docker "die" event.
	DockerEventDie DockerEvent = "die"

	// DockerEventDestroy represents the Docker "destroy" event.
	DockerEventDestroy DockerEvent = "destroy"

	// DockerEventConnect represents the Docker "connect" event.
	DockerEventConnect DockerEvent = "connect"
)

// A DockerEventHandler is type of docker event handler functions.
type DockerEventHandler func(event *events.Message) error

// A Monitor is the interface to implement low level monitoring functions on some well defined primitive.
type Monitor interface {

	// Start starts the monitor.
	Start() error

	// Stop Stops the monitor.
	Stop() error

	// AddHandler adds a new event handler function to the monitor.
	AddHandler(event DockerEvent, handler DockerEventHandler)
}

// A ProcessingUnitsHandler is responsible for monitoring creation and deletion of ProcessingUnits.
type ProcessingUnitsHandler interface {

	// HandleCreate handles the create ProcessingUnit event.
	HandleCreate(contextID string, runtimeInfo *policy.PURuntime) <-chan error

	// HandleDelete handles the delete ProcessingUnit event.
	HandleDelete(contextID string) <-chan error
}
