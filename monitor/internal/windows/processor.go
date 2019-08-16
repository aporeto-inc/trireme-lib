// +build windows

package windowsmonitor

import (
	"context"

	"go.aporeto.io/trireme-lib/common"
)

type windowsProcessor struct {
}

// Start processes PU start events
func (w *windowsProcessor) Start(ctx context.Context, eventInfo *common.EventInfo) error {
	return nil
}

// Event processes PU stop events
func (w *windowsProcessor) Stop(ctx context.Context, eventInfo *common.EventInfo) error {
	return nil
}

// Create process a PU create event
func (w *windowsProcessor) Create(ctx context.Context, eventInfo *common.EventInfo) error {
	return nil
}

// Event process a PU destroy event
func (w *windowsProcessor) Destroy(ctx context.Context, eventInfo *common.EventInfo) error {
	return nil
}

// Event processes a pause event
func (w *windowsProcessor) Pause(ctx context.Context, eventInfo *common.EventInfo) error {
	return nil
}

// Resync resyncs all PUs handled by this processor
func (w *windowsProcessor) Resync(ctx context.Context, EventInfo *common.EventInfo) error {
	return nil
}
