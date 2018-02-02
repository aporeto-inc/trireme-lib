package processor

import (
	"context"

	"github.com/aporeto-inc/trireme-lib/common"
)

// Processor is a generic interface that processes monitor events using
// a normalized event structure.
type Processor interface {

	// Start processes PU start events
	Start(ctx context.Context, eventInfo *common.EventInfo) error

	// Event processes PU stop events
	Stop(ctx context.Context, eventInfo *common.EventInfo) error

	// Create process a PU create event
	Create(ctx context.Context, eventInfo *common.EventInfo) error

	// Event process a PU destroy event
	Destroy(ctx context.Context, eventInfo *common.EventInfo) error

	// Event processes a pause event
	Pause(ctx context.Context, eventInfo *common.EventInfo) error

	// ReSync resyncs all PUs handled by this processor
	ReSync(ctx context.Context, EventInfo *common.EventInfo) error
}
