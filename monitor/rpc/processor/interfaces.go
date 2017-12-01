package processor

import "github.com/aporeto-inc/trireme-lib/monitor/rpc/eventinfo"

// Processor is a generic interface that processes monitor events using
// a normalized event structure.
type Processor interface {

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
