package cnimonitor

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/contextstore"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
)

// LinuxProcessor captures all the monitor processor information
// It implements the MonitorProcessor interface of the rpc monitor
type CniProcessor struct {
	collector         collector.EventCollector
	puHandler         monitor.ProcessingUnitsHandler
	metadataExtractor rpcmonitor.RPCMetadataExtractor
	contextStore      contextstore.ContextStore
}

// NewCniProcessor initializes a processor
func NewCniProcessor(collector collector.EventCollector, puHandler monitor.ProcessingUnitsHandler, metadataExtractor rpcmonitor.RPCMetadataExtractor) *CniProcessor {

	return &CniProcessor{
		collector:         collector,
		puHandler:         puHandler,
		metadataExtractor: metadataExtractor,
		contextStore:      contextstore.NewContextStore(),
	}
}

// Create handles create events
func (p *CniProcessor) Create(eventInfo *rpcmonitor.EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	return p.puHandler.HandlePUEvent(contextID, monitor.EventCreate)
}

// Start handles start events
func (p *CniProcessor) Start(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return err
	}

	runtimeInfo, err := p.metadataExtractor(eventInfo)
	if err != nil {
		return err
	}

	if err = p.puHandler.SetPURuntime(contextID, runtimeInfo); err != nil {
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
	return p.contextStore.StoreContext(contextID, eventInfo)
}

// Stop handles a stop event
func (p *CniProcessor) Stop(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	if !stringp.HasPrefix(contextID, cgnetclp.TriremeBasePath) || contextID == cgnetclp.TriremeBasePath {
		return nil
	}

	contextID = contextID[stringp.LastIndex(contextID, "/"):]

	return p.puHandler.HandlePUEvent(contextID, monitor.EventStop)
}

// Destroy handles a destroy event
func (p *CniProcessor) Destroy(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	if !stringp.HasPrefix(contextID, cgnetclp.TriremeBasePath) || contextID == cgnetclp.TriremeBasePath {
		return nil
	}

	contextID = contextID[stringp.LastIndex(contextID, "/"):]

	contextStoreHdl := contextstore.NewContextStore()

	p.netclp.Deletebasepath(contextID)

	// Send the event upstream
	if err := p.puHandler.HandlePUEvent(contextID, monitor.EventDestroy); err != nil {
		zap.L().Warn("Failed to clean trireme ",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	//let us remove the cgroup files now
	if err := p.netclp.DeleteCgroup(contextID); err != nil {
		zap.L().Warn("Failed to clean netcls group",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	if err := contextStoreHdl.RemoveContext(contextID); err != nil {
		zap.L().Warn("Failed to clean cache while destroying process",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	return nil
}

// Pause handles a pause event
func (p *CniProcessor) Pause(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	return p.puHandler.HandlePUEvent(contextID, monitor.EventPause)
}

// generateContextID creates the contextID from the event information
func generateContextID(eventInfo *rpcmonitor.EventInfo) (string, error) {

	if eventInfo.PUID == "" {
		return "", fmt.Errorf("PUID is empty from eventInfo")
	}

	return eventInfo.PUID, nil
}
