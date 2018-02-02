package uidmonitor

import (
	"context"
	"fmt"
	"regexp"

	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/monitor/config"
	"github.com/aporeto-inc/trireme-lib/monitor/instance"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/registerer"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls"
	"github.com/aporeto-inc/trireme-lib/utils/contextstore"
)

// uidMonitor captures all the monitor processor information for a UIDLoginPU
// It implements the EventProcessor interface of the rpc monitor
type uidMonitor struct {
	proc *uidProcessor
}

// New returns a new implmentation of a monitor implmentation
func New() monitorinstance.Implementation {

	return &uidMonitor{
		proc: &uidProcessor{},
	}
}

// Start implements Implementation interface
func (u *uidMonitor) Run(ctx context.Context) error {

	if err := u.proc.config.IsComplete(); err != nil {
		return fmt.Errorf("uid: %s", err)
	}

	if err := u.ReSync(ctx); err != nil {
		return err
	}

	return nil
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (u *uidMonitor) SetupConfig(registerer registerer.Registerer, cfg interface{}) error {

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
	u.proc.netcls = cgnetcls.NewCgroupNetController(uidConfig.ReleasePath)
	u.proc.contextStore = contextstore.NewFileContextStore(uidConfig.StoredPath, u.proc.RemapData)
	u.proc.storePath = uidConfig.StoredPath
	u.proc.regStart = regexp.MustCompile("^[a-zA-Z0-9_].{0,11}$")
	u.proc.regStop = regexp.MustCompile("^/trireme/[a-zA-Z0-9_].{0,11}$")
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
func (u *uidMonitor) SetupHandlers(m *config.ProcessorConfig) {

	u.proc.config = m
}

func (u *uidMonitor) ReSync(ctx context.Context) error {

	return u.proc.ReSync(ctx, nil)
}
