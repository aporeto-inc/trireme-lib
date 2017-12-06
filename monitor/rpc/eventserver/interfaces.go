package eventserver

import (
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/events"
)

// String constants that can be used while making an RPC call.
const (
	EventProcessorHandleEvent = "EventServer.HandleEvent"
)

// Processor is an interface that can be invoked over RPC.
type Processor interface {

	// HandleEvent Gets called when clients generate events.
	HandleEvent(eventInfo *events.EventInfo, result *events.EventResponse) error
}
