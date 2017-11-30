package cnimonitor

import (
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/internal/contextstore"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/monitor/eventinfo"
)

// CniProcessor captures all the monitor processor information
// It implements the EventProcessor interface of the rpc monitor
type CniProcessor struct {
	collector         collector.EventCollector
	puHandler         monitor.ProcessingUnitsHandler
	metadataExtractor eventinfo.EventMetadataExtractor
	contextStore      contextstore.ContextStore
}

// NewCniProcessor initializes a processor
func NewCniProcessor(collector collector.EventCollector, puHandler monitor.ProcessingUnitsHandler, metadataExtractor eventinfo.EventMetadataExtractor) *CniProcessor {

	contextStorePath := "/var/run/trireme/cni"

	return &CniProcessor{
		collector:         collector,
		puHandler:         puHandler,
		metadataExtractor: metadataExtractor,
		contextStore:      contextstore.NewFileContextStore(contextStorePath),
	}
}

// Create handles create events
func (p *CniProcessor) Create(eventInfo *eventinfo.EventInfo) error {
	fmt.Printf("Create: %+v \n", eventInfo)
	return nil
}

// Start handles start events
func (p *CniProcessor) Start(eventInfo *eventinfo.EventInfo) error {
	fmt.Printf("Start: %+v \n", eventInfo)
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return err
	}

	runtimeInfo, err := p.metadataExtractor(eventInfo)
	if err != nil {
		return err
	}

	if err = p.puHandler.CreatePURuntime(contextID, runtimeInfo); err != nil {
		return err
	}

	defaultIP, _ := runtimeInfo.DefaultIPAddress()

	if perr := p.puHandler.HandlePUEvent(contextID, monitor.EventStart); perr != nil {
		zap.L().Error("Failed to activate process", zap.Error(perr))
		return perr
	}

	p.collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: defaultIP,
		Tags:      runtimeInfo.Tags(),
		Event:     collector.ContainerStart,
	})

	// Store the state in the context store for future access
	return p.contextStore.Store(contextID, eventInfo)
}

// Stop handles a stop event
func (p *CniProcessor) Stop(eventInfo *eventinfo.EventInfo) error {
	fmt.Printf("Stop: %+v \n", eventInfo)
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	return p.puHandler.HandlePUEvent(contextID, monitor.EventStop)
}

// Destroy handles a destroy event
func (p *CniProcessor) Destroy(eventInfo *eventinfo.EventInfo) error {
	fmt.Printf("Destroy: %+v \n", eventInfo)
	return nil
}

// Pause handles a pause event
func (p *CniProcessor) Pause(eventInfo *eventinfo.EventInfo) error {
	fmt.Printf("Pause: %+v \n", eventInfo)
	return nil
}

// ReSync resyncs with all the existing services that were there before we start
func (p *CniProcessor) ReSync(e *eventinfo.EventInfo) error {

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

	walker, err := p.contextStore.Walk()
	if err != nil {
		return fmt.Errorf("error in accessing context store")
	}

	for {
		contextID := <-walker
		if contextID == "" {
			break
		}

		eventInfo := eventinfo.EventInfo{}
		if err := p.contextStore.Retrieve("/"+contextID, &eventInfo); err != nil {
			continue
		}

		// TODO: Better resync for CNI

		reacquired = append(reacquired, eventInfo.PUID)

		if err := p.Start(&eventInfo); err != nil {
			zap.L().Error("Failed to start PU ", zap.String("PUID", eventInfo.PUID))
			return fmt.Errorf("error in processing existing data: %s", err.Error())
		}

	}

	return nil
}

// generateContextID creates the contextID from the event information
func generateContextID(eventInfo *eventinfo.EventInfo) (string, error) {

	if eventInfo.PUID == "" {
		return "", fmt.Errorf("PUID is empty from eventInfo")
	}

	if len(eventInfo.PUID) < 12 {
		return "", fmt.Errorf("PUID smaller than 12 characters")
	}

	return eventInfo.PUID[:12], nil
}
