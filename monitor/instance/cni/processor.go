package cnimonitor

import (
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/monitor/config"
	"github.com/aporeto-inc/trireme-lib/monitor/extractors"

	"github.com/aporeto-inc/trireme-lib/utils/contextstore"
)

type cniProcessor struct {
	config            *config.ProcessorConfig
	metadataExtractor extractors.EventMetadataExtractor
	contextStore      contextstore.ContextStore
}

// Create handles create events
func (c *cniProcessor) Create(eventInfo *common.EventInfo) error {
	return nil
}

// Start handles start events
func (c *cniProcessor) Start(eventInfo *common.EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return err
	}

	runtimeInfo, err := c.metadataExtractor(eventInfo)
	if err != nil {
		return err
	}

	if err = c.config.Policy.CreatePURuntime(contextID, runtimeInfo); err != nil {
		return err
	}

	if err := c.config.Policy.HandlePUEvent(contextID, common.EventStart); err != nil {
		return err
	}

	c.config.Collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: runtimeInfo.IPAddresses(),
		Tags:      runtimeInfo.Tags(),
		Event:     collector.ContainerStart,
	})

	// Store the state in the context store for future access
	return c.contextStore.Store(contextID, eventInfo)
}

// Stop handles a stop event
func (c *cniProcessor) Stop(eventInfo *common.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("unable to generate context id: %s", err)
	}

	return c.config.Policy.HandlePUEvent(contextID, common.EventStop)
}

// Destroy handles a destroy event
func (c *cniProcessor) Destroy(eventInfo *common.EventInfo) error {
	return nil
}

// Pause handles a pause event
func (c *cniProcessor) Pause(eventInfo *common.EventInfo) error {
	return nil
}

// ReSync resyncs with all the existing services that were there before we start
func (c *cniProcessor) ReSync(e *common.EventInfo) error {

	deleted := []string{}
	reacquired := []string{}

	defer func() {
		if len(deleted) > 0 {
			zap.L().Info("Deleted dead contexts", zap.String("Context List", strings.Join(deleted, ",")))
		}
		if len(reacquired) > 0 {
			zap.L().Info("Reacquired contexts", zap.String("Context List", strings.Join(reacquired, ",")))
		}
	}()

	walker, err := c.contextStore.Walk()
	if err != nil {
		return fmt.Errorf("unable to walk the context store: %s", err)
	}

	for {
		contextID := <-walker
		if contextID == "" {
			break
		}

		eventInfo := common.EventInfo{}
		if err := c.contextStore.Retrieve("/"+contextID, &eventInfo); err != nil {
			continue
		}

		// TODO: Better resync for CNI

		reacquired = append(reacquired, eventInfo.PUID)

		if err := c.Start(&eventInfo); err != nil {
			return fmt.Errorf("error in processing existing data: %s", err)
		}

	}

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
