package uidmonitor

import (
	"context"
	"fmt"
	"regexp"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/registerer"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.aporeto.io/trireme-lib/utils/cgnetcls"
)

// UIDMonitor captures all the monitor processor information for a UIDLoginPU
// It implements the EventProcessor interface of the rpc monitor
type UIDMonitor struct {
	proc *uidProcessor
}

// New returns a new implmentation of a monitor implmentation
func New() *UIDMonitor {

	return &UIDMonitor{
		proc: &uidProcessor{},
	}
}

// Run implements Implementation interface
func (u *UIDMonitor) Run(ctx context.Context) error {

	if err := u.proc.config.IsComplete(); err != nil {
		return fmt.Errorf("uid: %s", err)
	}

	if err := u.Resync(ctx); err != nil {
		return err
	}

	return nil
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (u *UIDMonitor) SetupConfig(registerer registerer.Registerer, cfg interface{}) error {

	defaultConfig := DefaultConfig()
	if cfg == nil {
		cfg = defaultConfig
	}

	uidConfig, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified")
	}

	if registerer != nil {
		if err := registerer.RegisterProcessor(common.UIDLoginPU, u.proc); err != nil {
			return err
		}
	}

	// Setup defaults
	uidConfig = SetupDefaultConfig(uidConfig)

	// Setup config
	u.proc.netcls = cgnetcls.NewCgroupNetController(common.TriremeUIDCgroupPath, uidConfig.ReleasePath)
	u.proc.regStart = regexp.MustCompile("^[a-zA-Z0-9_]{1,11}$")
	u.proc.regStop = regexp.MustCompile("^/trireme/[a-zA-Z0-9_]{1,11}$")
	u.proc.putoPidMap = cache.NewCache("putoPidMap")
	u.proc.pidToPU = cache.NewCache("pidToPU")
	u.proc.metadataExtractor = uidConfig.EventMetadataExtractor
	if u.proc.metadataExtractor == nil {
		return fmt.Errorf("Unable to setup a metadata extractor")
	}

	return nil
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (u *UIDMonitor) SetupHandlers(m *config.ProcessorConfig) {

	u.proc.config = m
}

// Resync asks the monitor to do a resync
func (u *UIDMonitor) Resync(ctx context.Context) error {
	return u.proc.Resync(ctx, nil)
}
