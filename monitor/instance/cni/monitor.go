package cnimonitor

import (
	"fmt"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/internal/contextstore"
	"github.com/aporeto-inc/trireme-lib/monitor/instance"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/events"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/processor"
)

// Config is the configuration options to start a CNI monitor
type Config struct {
	EventMetadataExtractor events.EventMetadataExtractor
	ContextStorePath       string
}

// DefaultConfig provides a default configuration
func DefaultConfig() *Config {
	return &Config{
		EventMetadataExtractor: DockerMetadataExtractor,
		ContextStorePath:       "/var/run/trireme/cni",
	}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(cniConfig *Config) *Config {

	defaultConfig := DefaultConfig()

	if cniConfig.ContextStorePath == "" {
		cniConfig.ContextStorePath = defaultConfig.ContextStorePath
	}
	if cniConfig.EventMetadataExtractor == nil {
		cniConfig.EventMetadataExtractor = defaultConfig.EventMetadataExtractor
	}

	return cniConfig
}

// cniMonitor captures all the monitor processor information
// It implements the EventProcessor interface of the rpc monitor
type cniMonitor struct {
	proc *cniProcessor
}

// New returns a new implmentation of a monitor implmentation
func New() monitorinstance.Implementation {

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

	if err := c.ReSync(); err != nil {
		return err
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

	defaultConfig := DefaultConfig()
	if cfg == nil {
		cfg = defaultConfig
	}

	cniConfig, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified")
	}

	if registerer != nil {
		registerer.RegisterProcessor(constants.KubernetesPU, c.proc)
	}

	// Setup defaults
	cniConfig = SetupDefaultConfig(cniConfig)

	// Setup configuration
	c.proc.contextStore = contextstore.NewFileContextStore(cniConfig.ContextStorePath)
	if c.proc.contextStore == nil {
		return fmt.Errorf("Unable to create new context store")
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
	puHandler monitorinstance.ProcessingUnitsHandler,
	syncHandler monitorinstance.SynchronizationHandler,
) {

	c.proc.collector = collector
	c.proc.puHandler = puHandler
	c.proc.syncHandler = syncHandler
}

func (c *cniMonitor) ReSync() error {

	// TODO: Implement reSync
	return fmt.Errorf("reSync not implemented")
}
