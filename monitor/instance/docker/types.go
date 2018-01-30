package dockermonitor

import (
	"time"

	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
)

// Event is the type of various docker events.
type Event string

const (
	// EventCreate represents the Docker "create" event.
	EventCreate Event = "create"

	// EventStart represents the Docker "start" event.
	EventStart Event = "start"

	// EventDie represents the Docker "die" event.
	EventDie Event = "die"

	// EventDestroy represents the Docker "destroy" event.
	EventDestroy Event = "destroy"

	// EventPause represents the Docker "pause" event.
	EventPause Event = "pause"

	// EventUnpause represents the Docker "unpause" event.
	EventUnpause Event = "unpause"

	// EventConnect represents the Docker "connect" event.
	EventConnect Event = "connect"

	// DockerClientVersion is the version sent out as the client
	DockerClientVersion = "v1.23"

	// dockerPingTimeout is the time to wait for a ping to succeed.
	dockerPingTimeout = 2 * time.Second

	// dockerRetryTimer is the time after which we will retry to bring docker up.
	dockerRetryTimer = 10 * time.Second

	// dockerInitializationWait is the time after which we will retry to bring docker up.
	dockerInitializationWait = 2 * dockerRetryTimer
)
const (
	cstorePath = "/var/run/trireme/docker"
)

//StoredContext is the format of the data stored in the contextstore
type StoredContext struct {
	containerInfo *types.ContainerJSON
	Tags          *policy.TagStore
}

// A EventHandler is type of docker event handler functions.
type EventHandler func(event *events.Message) error
