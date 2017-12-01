package eventserver

import (
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/eventinfo"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/processor"
)

// String constants that can be used while making an RPC call.
const (
	EventProcessorHandleEvent = "EventServer.HandleEvent"
)

// EventResponse encapsulate the error response if any.
type EventResponse struct {
	Error string
}

// A EventHandler is type of event handler functions.
type EventHandler func(*eventinfo.EventInfo) error

// Processor is an interface that can be invoked over RPC.
type Processor interface {

	// HandleEvent Gets called when clients generate events.
	HandleEvent(eventInfo *eventinfo.EventInfo, result *EventResponse) error
}

// Registerer inteface allows event processors to register themselves with the event server.
type Registerer interface {

	// Register Processor registers event processors for a certain type of PU
	RegisterProcessor(puType constants.PUType, p processor.EventProcessor) error
}
