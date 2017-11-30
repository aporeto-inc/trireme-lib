package monitor

import (
	"github.com/aporeto-inc/trireme-lib/monitor/eventinfo"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// A Monitor is the interface to implement low level monitoring functions on some well defined primitive.
type Monitor interface {

	// SetupHandlers sets up handlers for monitors to invoke for various events such as
	// processing unit events and synchronization events. This will be called before Start()
	// by the consumer of the monitor
	SetupHandlers(puHandler ProcessingUnitsHandler, syncHandler SynchronizationHandler)

	// Start starts the monitor.
	Start() error

	// Stop Stops the monitor.
	Stop() error
}

// EventProcessor is a generic interface that processes monitor events using
// a normalized event structure.
type EventProcessor interface {

	// Start processes PU start events
	Start(eventInfo *eventinfo.EventInfo) error

	// Event processes PU stop events
	Stop(eventInfo *eventinfo.EventInfo) error

	// Create process a PU create event
	Create(eventInfo *eventinfo.EventInfo) error

	// Event process a PU destroy event
	Destroy(eventInfo *eventinfo.EventInfo) error

	// Event processes a pause event
	Pause(eventInfo *eventinfo.EventInfo) error

	// ReSync resyncs all PUs handled by this processor
	ReSync(EventInfo *eventinfo.EventInfo) error
}

// EventProcessorMonitor is a combination interface as implmented by some monitors
type EventProcessorMonitor interface {
	Monitor
	EventProcessor
}

// A ProcessingUnitsHandler must be implemnted by the monitor instantiators or components thereof.
type ProcessingUnitsHandler interface {

	// CreatePURuntime is called when a monitor detects creation of a new ProcessingUnit.
	CreatePURuntime(contextID string, runtimeInfo *policy.PURuntime) error

	// HandlePUEvent is called by all monitors when a PU event is generated. The implementer
	// is responsible to update all components by explicitly adding a new PU.
	HandlePUEvent(contextID string, event Event) error
}

// A SynchronizationHandler must be implemnted by the monitor instantiators or components thereof.
type SynchronizationHandler interface {

	// HandleSynchronization handles a synchronization routine.
	HandleSynchronization(contextID string, state State, RuntimeReader policy.RuntimeReader, syncType SynchronizationType) error

	// HandleSynchronizationComplete is called when a synchronization job is complete.
	HandleSynchronizationComplete(syncType SynchronizationType)
}
