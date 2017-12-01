package monitorimpl

import (
	"github.com/aporeto-inc/trireme-lib"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/eventserver"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// Implementation for a monitor.
type Implementation interface {

	// Start starts the monitor implementation.
	Start() error

	// Stop Stops the monitor implementation.
	Stop() error

	// SetupConfig provides a configuration to implmentations. Every implmentation
	// can have its own config type.
	SetupConfig(registerer eventserver.Registerer, cfg interface{}) error

	// SetupHandlers sets up handlers for monitors to invoke for various events such as
	// processing unit events and synchronization events. This will be called before Start()
	// by the consumer of the monitor
	SetupHandlers(collector trireme.EventCollector, puHandler ProcessingUnitsHandler, syncHandler SynchronizationHandler)
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

// Event represents the event picked up by the monitor.
type Event string

const (
	// EventStart is the event generated when a PU starts.
	EventStart Event = "start"

	// EventStop is the event generated when a PU stops/dies.
	EventStop Event = "stop"

	// EventCreate is the event generated when a PU gets created.
	EventCreate Event = "create"

	// EventDestroy is the event generated when a PU is definitely removed.
	EventDestroy Event = "destroy"

	// EventPause is the event generated when a PU is set to pause.
	EventPause Event = "pause"

	// EventUnpause is the event generated when a PU is unpaused.
	EventUnpause Event = "unpause"

	// EventResync instructs the processors to resync
	EventResync Event = "resync"
)

// A State describes the state of the PU.
type State int

const (
	// StateStarted is the state of a started PU.
	StateStarted State = iota + 1

	// StateStopped is the state of stopped PU.
	StateStopped

	// StatePaused is the state of a paused PU.
	StatePaused

	// StateDestroyed is the state of destroyed PU.
	StateDestroyed

	// StateUnknwown is the state of PU in an unknown state.
	StateUnknwown
)

// A SynchronizationType represents the type of synchronization job.
type SynchronizationType int

const (
	// SynchronizationTypeInitial indicates the initial synchronization job.
	SynchronizationTypeInitial SynchronizationType = iota + 1

	// SynchronizationTypePeriodic indicates subsequent synchronization jobs.
	SynchronizationTypePeriodic
)
