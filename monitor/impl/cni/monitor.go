package cnimonitor

import (
	"fmt"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/internal/contextstore"
	"github.com/aporeto-inc/trireme-lib/monitor/impl"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/events"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/processor"
)

// Config is the configuration options to start a CNI monitor
type Config struct {
	EventMetadataExtractor events.EventMetadataExtractor
	ContextStorePath       string
}

// cniMonitor captures all the monitor processor information
// It implements the EventProcessor interface of the rpc monitor
type cniMonitor struct {
	proc *cniProcessor
}

// New returns a new implmentation of a monitor implmentation
func New() monitorimpl.Implementation {

	return &cniMonitor{
		proc: &cniProcessor{},
	}
}

// Start implements Implementation interface
func (c *cniMonitor) Start() error {

	if c.proc.collector == nil {
		return fmt.Errorf("Missing configuration: collector")
	}

	if c.proc.syncHandler == nil {
		return fmt.Errorf("Missing configuration: syncHandler")
	}

	if c.proc.puHandler == nil {
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
func (c *cniMonitor) SetupConfig(registerer processor.Registerer, cfg interface{}) error {

	if cfg == nil {
		cfg = &Config{}
	}

	cniConfig, ok := cfg.(Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified")
	}

	if registerer != nil {
		registerer.RegisterProcessor(constants.KubernetesPU, c.proc)
	}

	if cniConfig.ContextStorePath == "" {
		cniConfig.ContextStorePath = "/var/run/trireme/cni"
	}
	c.proc.contextStore = contextstore.NewFileContextStore(cniConfig.ContextStorePath)
	if c.proc.contextStore == nil {
		return fmt.Errorf("Unable to create new context store")
	}

	if cniConfig.EventMetadataExtractor == nil {
		cniConfig.EventMetadataExtractor = DockerMetadataExtractor
	}
	c.proc.metadataExtractor = cniConfig.EventMetadataExtractor
	if c.proc.metadataExtractor == nil {
		return fmt.Errorf("Unable to setup a metadata extractor")
	}

	return nil
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (c *cniMonitor) SetupHandlers(
	collector collector.EventCollector,
	puHandler monitorimpl.ProcessingUnitsHandler,
	syncHandler monitorimpl.SynchronizationHandler) {

	c.proc.collector = collector
	c.proc.puHandler = puHandler
	c.proc.syncHandler = syncHandler
}
