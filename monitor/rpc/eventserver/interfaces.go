package eventserver

import (
	"context"

	"github.com/aporeto-inc/trireme-lib/common"
)

// String constants that can be used while making an RPC call.
const (
	EventProcessorHandleEvent = "EventServer.HandleEvent"
)

// Processor is an interface that can be invoked over RPC.
type Processor interface {

	// SetContext sets the context of the processor for all event handling
	SetContext(ctx context.Context)

	// HandleEvent Gets called when clients generate events.
	HandleEvent(eventInfo *common.EventInfo, result *common.EventResponse) error
}
