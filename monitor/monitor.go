package monitor

// Event represents the event picked up by the monitor.
type Event string

// StartEvent is the event generated when a PU starts.
const StartEvent = "start"

// StopEvent is the event generated when a PU starts.
const StopEvent = "stop"

// CreateEvent is the event generated when a PU starts.
const CreateEvent = "create"

// DestroyEvent is the event generated when a PU starts.
const DestroyEvent = "destroy"

// PauseEvent is the event generated when a PU starts.
const PauseEvent = "pause"

// UnpauseEvent is the event generated when a PU starts.
const UnpauseEvent = "unpause"
