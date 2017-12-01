package cnimonitor

import (
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/internal/contextstore"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/eventinfo"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/eventserver"
)

// Config is the configuration options to start a CNI monitor
type Config struct {
	EventMetadataExtractor eventinfo.EventMetadataExtractor
	ContextStorePath       string
}

// cniMonitor captures all the monitor processor information
// It implements the EventProcessor interface of the rpc monitor
type cniMonitor struct {
	collector         collector.EventCollector
	puHandler         monitorimpl.ProcessingUnitsHandler
	syncHandler       monitorimpl.SynchronizationHandler
	metadataExtractor eventinfo.EventMetadataExtractor
	contextStore      contextstore.ContextStore
}

// New returns a new implmentation of a monitor implmentation
func New() monitorimpl.Implementation {

	return &cniMonitor{}
}

// Start implements Implementation interface
func (c *cniMonitor) Start() error {

	if c.collector == nil {
		return fmt.Errorf("Missing configuration: collector")
	}

	if c.syncHandler == nil {
		return fmt.Errorf("Missing configuration: syncHandler")
	}

	if c.puHandler == nil {
		return fmt.Errorf("Missing configuration: puHandler")
	}

	return nil
}

// Stop implements Implementation interface
func (c *cniMonitor) Stop() error {

	return nil
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (c *cniMonitor) SetupConfig(registerer eventserver.Registerer, cfg interface{}) error {

	if cfg == nil {
		cfg = &Config{}
	}

	cniConfig, ok := cfg.(Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified")
	}

	if registerer != nil {
		registerer.RegisterProcessor(constants.KubernetesPU, c)
	}

	if cniConfig.ContextStorePath == "" {
		cniConfig.ContextStorePath = "/var/run/trireme/cni"
	}
	c.contextStore = contextstore.NewFileContextStore(cniConfig.ContextStorePath)
	if c.contextStore == nil {
		return fmt.Errorf("Unable to create new context store")
	}

	if cniConfig.EventMetadataExtractor == nil {
		cniConfig.EventMetadataExtractor = DockerMetadataExtractor
	}
	c.metadataExtractor = cniConfig.EventMetadataExtractor
	if c.metadataExtractor == nil {
		return fmt.Errorf("Unable to setup a metadata extractor")
	}

	return nil
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (c *cniMonitor) SetupHandlers(
	collector trireme.EventCollector,
	puHandler monitor.ProcessingUnitsHandler,
	syncHandler monitor.SynchronizationHandler) {

	c.collector = collector
	c.puHandler = puHandler
	c.syncHandler = syncHandler
}

// Create handles create events
func (c *cniMonitor) Create(eventInfo *eventinfo.EventInfo) error {
	fmt.Printf("Create: %+v \n", eventInfo)
	return nil
}

// Start handles start events
func (c *cniMonitor) Start(eventInfo *eventinfo.EventInfo) error {
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
func (c *cniMonitor) Stop(eventInfo *eventinfo.EventInfo) error {
	fmt.Printf("Stop: %+v \n", eventInfo)
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	return p.puHandler.HandlePUEvent(contextID, monitor.EventStop)
}

// Destroy handles a destroy event
func (c *cniMonitor) Destroy(eventInfo *eventinfo.EventInfo) error {
	fmt.Printf("Destroy: %+v \n", eventInfo)
	return nil
}

// Pause handles a pause event
func (c *cniMonitor) Pause(eventInfo *eventinfo.EventInfo) error {
	fmt.Printf("Pause: %+v \n", eventInfo)
	return nil
}

// ReSync resyncs with all the existing services that were there before we start
func (c *cniMonitor) ReSync(e *eventinfo.EventInfo) error {

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
