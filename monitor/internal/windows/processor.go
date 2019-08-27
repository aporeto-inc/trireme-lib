// +build windows

package windowsmonitor

import (
	"context"
	"fmt"
	"regexp"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

type windowsProcessor struct {
	regStart          *regexp.Regexp
	regStop           *regexp.Regexp
	metadataExtractor extractors.EventMetadataExtractor
	config            *config.ProcessorConfig
	host              bool
}

// Start processes PU start events
func (w *windowsProcessor) Start(ctx context.Context, eventInfo *common.EventInfo) error {
	// Validate the PUID format. Additional validations TODO
	if !w.regStart.Match([]byte(eventInfo.PUID)) {
		return fmt.Errorf("invalid pu id: %s", eventInfo.PUID)
	}

	// Normalize to a nativeID context. This will become key for any recoveries
	// and it's an one way function.
	nativeID, err := w.generateContextID(eventInfo)
	if err != nil {
		return err
	}
	// Extract the metadata and create the runtime
	runtime, err := w.metadataExtractor(eventInfo)
	if err != nil {
		return err
	}

	// We need to send a create event to the policy engine.
	if err = w.config.Policy.HandlePUEvent(ctx, nativeID, common.EventCreate, runtime); err != nil {
		return fmt.Errorf("Unable to create PU: %s", err)
	}

	// We can now send a start event to the policy engine
	if err = w.config.Policy.HandlePUEvent(ctx, nativeID, common.EventStart, runtime); err != nil {
		return fmt.Errorf("Unable to start PU: %s", err)
	}
	return nil
}

// Event processes PU stop events
func (w *windowsProcessor) Stop(ctx context.Context, eventInfo *common.EventInfo) error {
	puID, err := w.generateContextID(eventInfo)
	if err != nil {
		return err
	}
	runtime := policy.NewPURuntimeWithDefaults()
	runtime.SetPUType(eventInfo.PUType)

	return w.config.Policy.HandlePUEvent(ctx, puID, common.EventStop, runtime)
}

// Create process a PU create event
func (w *windowsProcessor) Create(ctx context.Context, eventInfo *common.EventInfo) error {
	return fmt.Errorf("Use start directly for windows processes. Create not supported")
}

// Event process a PU destroy event
func (w *windowsProcessor) Destroy(ctx context.Context, eventInfo *common.EventInfo) error {
	puID, err := w.generateContextID(eventInfo)
	if err != nil {
		return err
	}
	runtime := policy.NewPURuntimeWithDefaults()
	runtime.SetPUType(eventInfo.PUType)

	// Send the event upstream
	if err := w.config.Policy.HandlePUEvent(ctx, puID, common.EventDestroy, runtime); err != nil {
		zap.L().Warn("Unable to clean trireme ",
			zap.String("puID", puID),
			zap.Error(err),
		)
	}
	return err
}

// Event processes a pause event
func (w *windowsProcessor) Pause(ctx context.Context, eventInfo *common.EventInfo) error {
	return fmt.Errorf("Use start directly for windows processes. Pause not supported")
}

// Resync resyncs all PUs handled by this processor
func (w *windowsProcessor) Resync(ctx context.Context, eventInfo *common.EventInfo) error {
	if eventInfo != nil {
		// If its a host service then use pu from eventInfo
		if eventInfo.HostService {
			runtime, err := w.metadataExtractor(eventInfo)
			if err != nil {
				return err
			}
			nativeID, err := w.generateContextID(eventInfo)
			if err != nil {
				return err
			}
			if err = w.config.Policy.HandlePUEvent(ctx, nativeID, common.EventStart, runtime); err != nil {
				return fmt.Errorf("Unable to start PU: %s", err)
			}
			return nil
		}
	}

	// TODO(windows): handle resync of windows process PU later?
	zap.L().Warn("Resync not handled")

	return nil
}

func (w *windowsProcessor) generateContextID(eventInfo *common.EventInfo) (string, error) {
	puID := eventInfo.PUID
	if eventInfo.Cgroup == "" {
		return puID, nil
	}

	return puID, nil

}
