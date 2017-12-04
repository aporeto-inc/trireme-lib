package monitorinstance

import (
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/events"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/processor"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// Common configuration for all monitors
type Config struct {
	Collector   collector.EventCollector
	PUHandler   ProcessingUnitsHandler
	SyncHandler SynchronizationHandler
	MergeTags   []string
}

// Implementation for a monitor.
type Implementation interface {

	// Start starts the monitor implementation.
	Start() error

	// Stop Stops the monitor implementation.
	Stop() error

	// SetupConfig provides a configuration to implmentations. Every implmentation
	// can have its own config type.
	SetupConfig(registerer processor.Registerer, cfg interface{}) error

	// SetupHandlers sets up handlers for monitors to invoke for various events such as
	// processing unit events and synchronization events. This will be called before Start()
	// by the consumer of the monitor
	SetupHandlers(c *Config)

	// ReSync should resynchronize PUs. This should be done while starting up.
	ReSync() error
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
