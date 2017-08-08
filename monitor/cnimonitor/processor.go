package cnimonitor

import (
	"fmt"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/contextstore"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
)

// CniProcessor captures all the monitor processor information
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
	fmt.Printf("Create: %+v \n", eventInfo)
	return nil
}

// Start handles start events
func (p *CniProcessor) Start(eventInfo *rpcmonitor.EventInfo) error {
	fmt.Printf("Start: %+v \n", eventInfo)
	return nil
}

// Stop handles a stop event
func (p *CniProcessor) Stop(eventInfo *rpcmonitor.EventInfo) error {
	fmt.Printf("Stop: %+v \n", eventInfo)
	return nil
}

// Destroy handles a destroy event
func (p *CniProcessor) Destroy(eventInfo *rpcmonitor.EventInfo) error {
	fmt.Printf("Destroy: %+v \n", eventInfo)
	return nil
}

// Pause handles a pause event
func (p *CniProcessor) Pause(eventInfo *rpcmonitor.EventInfo) error {
	fmt.Printf("Pause: %+v \n", eventInfo)
	return nil
}

// generateContextID creates the contextID from the event information
func generateContextID(eventInfo *rpcmonitor.EventInfo) (string, error) {

	if eventInfo.PUID == "" {
		return "", fmt.Errorf("PUID is empty from eventInfo")
	}

	return eventInfo.PUID, nil
}
