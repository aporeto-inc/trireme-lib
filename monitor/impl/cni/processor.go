package cnimonitor

import (
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/internal/contextstore"
	"github.com/aporeto-inc/trireme-lib/monitor/impl"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/events"
)

type cniProcessor struct {
	collector         collector.EventCollector
	puHandler         monitorimpl.ProcessingUnitsHandler
	syncHandler       monitorimpl.SynchronizationHandler
	metadataExtractor events.EventMetadataExtractor
	contextStore      contextstore.ContextStore
}

// Create handles create events
func (c *cniProcessor) Create(eventInfo *events.EventInfo) error {
	fmt.Printf("Create: %+v \n", eventInfo)
	return nil
}

// Start handles start events
func (c *cniProcessor) Start(eventInfo *events.EventInfo) error {
	fmt.Printf("Start: %+v \n", eventInfo)
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return err
	}

	runtimeInfo, err := c.metadataExtractor(eventInfo)
	if err != nil {
		return err
	}

	if err = c.puHandler.CreatePURuntime(contextID, runtimeInfo); err != nil {
		return err
	}

	defaultIP, _ := runtimeInfo.DefaultIPAddress()

	if perr := c.puHandler.HandlePUEvent(contextID, events.EventStart); perr != nil {
		zap.L().Error("Failed to activate process", zap.Error(perr))
		return perr
	}

	c.collector.CollectContainerEvent(&collector.ContainerRecord{
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
	fmt.Printf("Stop: %+v \n", eventInfo)
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	return c.puHandler.HandlePUEvent(contextID, events.EventStop)
}

// Destroy handles a destroy event
func (c *cniProcessor) Destroy(eventInfo *events.EventInfo) error {
	fmt.Printf("Destroy: %+v \n", eventInfo)
	return nil
}

// Pause handles a pause event
func (c *cniProcessor) Pause(eventInfo *events.EventInfo) error {
	fmt.Printf("Pause: %+v \n", eventInfo)
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
		return fmt.Errorf("error in accessing context store")
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
			zap.L().Error("Failed to start PU ", zap.String("PUID", eventInfo.PUID))
			return fmt.Errorf("error in processing existing data: %s", err.Error())
		}

	}

	return nil
}

// generateContextID creates the contextID from the event information
func generateContextID(eventInfo *events.EventInfo) (string, error) {

	if eventInfo.PUID == "" {
		return "", fmt.Errorf("PUID is empty from eventInfo")
	}

	if len(eventInfo.PUID) < 12 {
		return "", fmt.Errorf("PUID smaller than 12 characters")
	}

	return eventInfo.PUID[:12], nil
}
