package cnimonitor

import (
	"context"
	"fmt"

	"go.aporeto.io/trireme-lib/v11/common"
	"go.aporeto.io/trireme-lib/v11/monitor/config"
	"go.aporeto.io/trireme-lib/v11/monitor/extractors"
	"go.aporeto.io/trireme-lib/v11/monitor/registerer"
)

// Config is the configuration options to start a CNI monitor
type Config struct {
	EventMetadataExtractor extractors.EventMetadataExtractor
}

// DefaultConfig provides a default configuration
func DefaultConfig() *Config {
	return &Config{
		EventMetadataExtractor: DockerMetadataExtractor,
	}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(cniConfig *Config) *Config {

	defaultConfig := DefaultConfig()

	if cniConfig.EventMetadataExtractor == nil {
		cniConfig.EventMetadataExtractor = defaultConfig.EventMetadataExtractor
	}

	return cniConfig
}

// CniMonitor captures all the monitor processor information
// It implements the EventProcessor interface of the rpc monitor
type CniMonitor struct {
	proc *cniProcessor
}

// New returns a new implmentation of a monitor implmentation
func New() *CniMonitor {

	return &CniMonitor{
		proc: &cniProcessor{},
	}
}

// Run implements Implementation interface
func (c *CniMonitor) Run(ctx context.Context) error {

	return c.proc.config.IsComplete()
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (c *CniMonitor) SetupConfig(registerer registerer.Registerer, cfg interface{}) error {

	defaultConfig := DefaultConfig()
	if cfg == nil {
		cfg = defaultConfig
	}

	cniConfig, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified")
	}

	if registerer != nil {
		if err := registerer.RegisterProcessor(common.KubernetesPU, c.proc); err != nil {
			return err
		}
	}

	// Setup defaults
	cniConfig = SetupDefaultConfig(cniConfig)

	// Setup configuration
	c.proc.metadataExtractor = cniConfig.EventMetadataExtractor
	if c.proc.metadataExtractor == nil {
		return fmt.Errorf("Unable to setup a metadata extractor")
	}

	return nil
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (c *CniMonitor) SetupHandlers(m *config.ProcessorConfig) {

	c.proc.config = m
}

// Resync instructs the monitor to do a resync.
func (c *CniMonitor) Resync(ctx context.Context) error {

	// TODO: Implement resync
	return fmt.Errorf("resync not implemented")
}
