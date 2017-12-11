package cnimonitor

import (
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/utils/contextstore"
	"github.com/aporeto-inc/trireme-lib/rpc/events"
	"github.com/aporeto-inc/trireme-lib/rpc/processor"
)

type cniProcessor struct {
	config            *processor.Config
	metadataExtractor events.EventMetadataExtractor
	contextStore      contextstore.ContextStore
}

// Create handles create events
func (c *cniProcessor) Create(eventInfo *events.EventInfo) error {
	return nil
}

// Start handles start events
func (c *cniProcessor) Start(eventInfo *events.EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return err
	}

	runtimeInfo, err := c.metadataExtractor(eventInfo)
	if err != nil {
		return err
	}

	if err = c.config.PUHandler.CreatePURuntime(contextID, runtimeInfo); err != nil {
		return err
	}

	defaultIP, _ := runtimeInfo.DefaultIPAddress()

	if err := c.config.PUHandler.HandlePUEvent(contextID, events.EventStart); err != nil {
		return err
	}

	c.config.Collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: defaultIP,
		Tags:      runtimeInfo.Tags(),
		Event:     collector.ContainerStart,
	})

	// Store the state in the context store for future access
	return c.contextStore.Store(contextID, eventInfo)
}

// Stop handles a stop event
func (c *cniProcessor) Stop(eventInfo *events.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("unable to generate context id: %s", err)
	}

	return c.config.PUHandler.HandlePUEvent(contextID, events.EventStop)
}

// Destroy handles a destroy event
func (c *cniProcessor) Destroy(eventInfo *events.EventInfo) error {
	return nil
}

// Pause handles a pause event
func (c *cniProcessor) Pause(eventInfo *events.EventInfo) error {
	return nil
}

// ReSync resyncs with all the existing services that were there before we start
func (c *cniProcessor) ReSync(e *events.EventInfo) error {

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

		eventInfo := events.EventInfo{}
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
func generateContextID(eventInfo *events.EventInfo) (string, error) {

	if eventInfo.PUID == "" {
		return "", errors.New("puid is empty from event info")
	}

	if len(eventInfo.PUID) < 12 {
		return "", errors.New("puid smaller than 12 characters")
	}

	return eventInfo.PUID[:12], nil
}
