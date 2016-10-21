package monitor

import (
	"github.com/aporeto-inc/trireme/policy"
	"github.com/docker/docker/api/types"
)

// A Monitor is implementing a low level monitoring function on some well defined primitive.
type Monitor interface {
	Start() error
	Stop() error
}

// A ProcessingUnitsHandler is responsible for monitoring creation and deletion of ProcessingUnits.
type ProcessingUnitsHandler interface {
	HandleCreate(contextID string, runtimeInfo *policy.PURuntime) <-chan error
	HandleDelete(contextID string) <-chan error
}

// MetadataExtractor has the capability to translate Docker Information into a standard Trireme PURuntime struct.
type MetadataExtractor interface {
	ExtractMetadata(dockerInfo *types.ContainerJSON) (*policy.PURuntime, error)
}
