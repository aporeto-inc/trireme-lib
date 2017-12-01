package processor

import (
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/events"
)

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
