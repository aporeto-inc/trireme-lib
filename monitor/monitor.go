package monitor

// Event represents the event picked up by the monitor.
type Event string

// EventStart is the event generated when a PU starts.
const EventStart = "start"

// EventStop is the event generated when a PU stops/dies.
const EventStop = "stop"

// EventCreate is the event generated when a PU gets created.
const EventCreate = "create"

// EventDestroy is the event generated when a PU is definitely removed.
const EventDestroy = "destroy"

// EventPause is the event generated when a PU is set to pause.
const EventPause = "pause"

// EventUnpause is the event generated when a PU is unpaused.
const EventUnpause = "unpause"

// State describes the state of the PU.
type State string

// StateStarted is the event generated when a PU starts.
const StateStarted = "started"

// StateStopped is the event generated when a PU stops/dies.
const StateStopped = "stopped"

// StatePaused is the event generated when a PU gets created.
const StatePaused = "paused"

// StateUnknwown is the event generated when a PU is definitely removed.
const StateUnknwown = "unknown"

// StateDestroyed is the event generated when a PU is definitely removed.
const StateDestroyed = "destroyed"
