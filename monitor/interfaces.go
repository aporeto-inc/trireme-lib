package monitor

import (
	"github.com/aporeto-inc/trireme/policy"
	"github.com/docker/docker/api/types/events"
)

// A Monitor is the interface to implement low level monitoring functions on some well defined primitive.
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
