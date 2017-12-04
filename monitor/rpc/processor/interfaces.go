package processor

import (
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/events"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// Common configuration for all monitors
type Config struct {
	Collector   collector.EventCollector
	PUHandler   ProcessingUnitsHandler
	SyncHandler SynchronizationHandler
	MergeTags   []string
}

// A ProcessingUnitsHandler must be implemnted by the monitor instantiators or components thereof.
type ProcessingUnitsHandler interface {

	// CreatePURuntime is called when a monitor detects creation of a new ProcessingUnit.
	CreatePURuntime(contextID string, runtimeInfo *policy.PURuntime) error

	// HandlePUEvent is called by all monitors when a PU event is generated. The implementer
	// is responsible to update all components by explicitly adding a new PU.
	HandlePUEvent(contextID string, event events.Event) error
}

// A SynchronizationType represents the type of synchronization job.
type SynchronizationType int

const (
	// SynchronizationTypeInitial indicates the initial synchronization job.
	SynchronizationTypeInitial SynchronizationType = iota + 1

	// SynchronizationTypePeriodic indicates subsequent synchronization jobs.
	SynchronizationTypePeriodic
)

// A SynchronizationHandler must be implemnted by the monitor instantiators or components thereof.
type SynchronizationHandler interface {

	// HandleSynchronization handles a synchronization routine.
	HandleSynchronization(contextID string, state events.State, RuntimeReader policy.RuntimeReader, syncType SynchronizationType) error

	// HandleSynchronizationComplete is called when a synchronization job is complete.
	HandleSynchronizationComplete(syncType SynchronizationType)
}

// Processor is a generic interface that processes monitor events using
// a normalized event structure.
type Processor interface {

	// Start processes PU start events
	Start(eventInfo *events.EventInfo) error

	// Event processes PU stop events
	Stop(eventInfo *events.EventInfo) error

	// Create process a PU create event
	Create(eventInfo *events.EventInfo) error

	// Event process a PU destroy event
	Destroy(eventInfo *events.EventInfo) error

	// Event processes a pause event
	Pause(eventInfo *events.EventInfo) error

	// ReSync resyncs all PUs handled by this processor
	ReSync(EventInfo *events.EventInfo) error
}

// Registerer inteface allows event processors to register themselves with the event server.
type Registerer interface {

	// Register Processor registers event processors for a certain type of PU
	RegisterProcessor(puType constants.PUType, p Processor) error

	GetHandler(puType constants.PUType, e events.Event) (events.EventHandler, error)
}
