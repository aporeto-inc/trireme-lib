package monitor

import "github.com/aporeto-inc/trireme/policy"

// A Monitor is the interface to implement low level monitoring functions on some well defined primitive.
type Monitor interface {

	// Start starts the monitor.
	Start() error

	// Stop Stops the monitor.
	Stop() error
}

// A ProcessingUnitsHandler is responsible for monitoring creation and deletion of ProcessingUnits.
type ProcessingUnitsHandler interface {

	// HandleCreate handles the create ProcessingUnit event.
	HandleCreate(contextID string, runtimeInfo *policy.PURuntime) <-chan error

	// HandleDelete handles the delete ProcessingUnit event.
	HandleDelete(contextID string) <-chan error

	// HandleDelete handles the delete ProcessingUnit event.
	HandleDestroy(contextID string) <-chan error
}
