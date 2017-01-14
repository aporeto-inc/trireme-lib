package monitor

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
