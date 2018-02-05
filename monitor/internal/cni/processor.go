package cnimonitor

import (
	"context"
	"errors"
	"fmt"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/monitor/config"
	"github.com/aporeto-inc/trireme-lib/monitor/extractors"
	"github.com/aporeto-inc/trireme-lib/policy"
)

type cniProcessor struct {
	config            *config.ProcessorConfig
	metadataExtractor extractors.EventMetadataExtractor
}

// Create handles create events
func (c *cniProcessor) Create(ctx context.Context, eventInfo *common.EventInfo) error {
	return nil
}

// Start handles start events
func (c *cniProcessor) Start(ctx context.Context, eventInfo *common.EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return err
	}

	runtimeInfo, err := c.metadataExtractor(eventInfo)
	if err != nil {
		return err
	}

	if err := c.config.Policy.HandlePUEvent(ctx, contextID, common.EventCreate, runtimeInfo); err != nil {
		return err
	}

	if err := c.config.Policy.HandlePUEvent(ctx, contextID, common.EventStart, runtimeInfo); err != nil {
		return err
	}

	c.config.Collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: runtimeInfo.IPAddresses(),
		Tags:      runtimeInfo.Tags(),
		Event:     collector.ContainerStart,
	})

	return nil
}

// Stop handles a stop event
func (c *cniProcessor) Stop(ctx context.Context, eventInfo *common.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("unable to generate context id: %s", err)
	}

	runtime := policy.NewPURuntimeWithDefaults()

	if err := c.config.Policy.HandlePUEvent(ctx, contextID, common.EventStop, runtime); err != nil {
		return err
	}

	return c.config.Policy.HandlePUEvent(ctx, contextID, common.EventDestroy, runtime)
}

// Destroy handles a destroy event
func (c *cniProcessor) Destroy(ctx context.Context, eventInfo *common.EventInfo) error {
	return nil
}

// Pause handles a pause event
func (c *cniProcessor) Pause(ctx context.Context, eventInfo *common.EventInfo) error {
	return nil
}

// ReSync resyncs with all the existing services that were there before we start
func (c *cniProcessor) ReSync(ctx context.Context, e *common.EventInfo) error {
	return nil
}

// generateContextID creates the contextID from the event information
func generateContextID(eventInfo *common.EventInfo) (string, error) {

	if eventInfo.PUID == "" {
		return "", errors.New("puid is empty from event info")
	}

	if len(eventInfo.PUID) < 12 {
		return "", errors.New("puid smaller than 12 characters")
	}

	return eventInfo.PUID[:12], nil
}
