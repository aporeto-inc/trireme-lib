package monitor

import (
	"github.com/aporeto-inc/trireme/policy"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
)

// A Monitor is implementing a low level monitoring function on some well defined primitive.
type Monitor interface {
	Start() error
	Stop() error
	AddHandler(event string, handler func(event *events.Message) error)
}

// A ProcessingUnitsHandler is responsible for monitoring creation and deletion of ProcessingUnits.
type ProcessingUnitsHandler interface {
	HandleCreate(contextID string, runtimeInfo *policy.PURuntime) <-chan error
	HandleDelete(contextID string) <-chan error
}

// DockerMetadataExtractor has the capability to translate Docker Information into a standard Trireme PURuntime struct.
type DockerMetadataExtractor interface {
	ExtractMetadata(dockerInfo *types.ContainerJSON) (*policy.PURuntime, error)
}
