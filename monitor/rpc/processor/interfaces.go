package processor

import "github.com/aporeto-inc/trireme-lib/common"

// Processor is a generic interface that processes monitor events using
// a normalized event structure.
type Processor interface {

	// Start processes PU start events
	Start(eventInfo *common.EventInfo) error

	// Event processes PU stop events
	Stop(eventInfo *common.EventInfo) error

	// Create process a PU create event
	Create(eventInfo *common.EventInfo) error

	// Event process a PU destroy event
	Destroy(eventInfo *common.EventInfo) error

	// Event processes a pause event
	Pause(eventInfo *common.EventInfo) error

	// ReSync resyncs all PUs handled by this processor
	ReSync(EventInfo *common.EventInfo) error
}
