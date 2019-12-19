package dockermonitor

import (
	"context"
	"time"

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
	dockerRetryTimer = 2 * time.Second

	// dockerInitializationWait is the time after which we will retry to bring docker up.
	dockerInitializationWait = 2 * dockerRetryTimer
)

// A EventHandler is type of docker event handler functions.
type EventHandler func(ctx context.Context, event *events.Message) error

// DockerClientInterface creates an interface for the docker client so that we can do tests.
type DockerClientInterface interface {
	// ContainerInspect corresponds to the ContainerInspect of docker.
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)

	// ContainerList abstracts the ContainerList as interface.
	ContainerList(ctx context.Context, options types.ContainerListOptions) ([]types.Container, error)

	// ContainerStop abstracts the ContainerStop as interface.
	ContainerStop(ctx context.Context, containerID string, timeout *time.Duration) error

	// Events abstracts the Event method as an interface.
	Events(ctx context.Context, options types.EventsOptions) (<-chan events.Message, <-chan error)

	// Ping abstracts the Event method as an interface
	Ping(ctx context.Context) (types.Ping, error)
}
