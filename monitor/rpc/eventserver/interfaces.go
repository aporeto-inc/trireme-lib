package eventserver

import (
	"github.com/aporeto-inc/trireme-lib/common"
)

// String constants that can be used while making an RPC call.
const (
	EventProcessorHandleEvent = "EventServer.HandleEvent"
)

// Processor is an interface that can be invoked over RPC.
type Processor interface {

	// HandleEvent Gets called when clients generate events.
	HandleEvent(eventInfo *common.EventInfo, result *common.EventResponse) error
}
