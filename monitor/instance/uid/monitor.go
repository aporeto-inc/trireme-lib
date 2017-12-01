package uidmonitor

import (
	"fmt"
	"regexp"

	"github.com/aporeto-inc/trireme-lib/cache"
	"github.com/aporeto-inc/trireme-lib/cgnetcls"
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
	StoredPath             string
	ReleasePath            string
}

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
func (u *uidMonitor) Start() error {

	if u.proc.collector == nil {
		return fmt.Errorf("Missing configuration: collector")
	}

	if u.proc.syncHandler == nil {
		return fmt.Errorf("Missing configuration: syncHandler")
	}

	if u.proc.puHandler == nil {
		return fmt.Errorf("Missing configuration: puHandler")
	}

	return nil
}

// Stop implements Implementation interface
func (u *uidMonitor) Stop() error {

	return nil
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (u *uidMonitor) SetupConfig(registerer processor.Registerer, cfg interface{}) error {

	if cfg == nil {
		cfg = &Config{}
	}

	uidConfig, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified")
	}

	if registerer != nil {
		registerer.RegisterProcessor(constants.UIDLoginPU, u.proc)
	}

	if uidConfig.ReleasePath == "" {
		uidConfig.ReleasePath = "/var/lib/aporeto/cleaner"
	}
	u.proc.netcls = cgnetcls.NewCgroupNetController(uidConfig.ReleasePath)

	if uidConfig.StoredPath == "" {
		uidConfig.StoredPath = "/var/run/trireme/uid"
	}
	u.proc.contextStore = contextstore.NewFileContextStore(uidConfig.StoredPath)
	u.proc.storePath = uidConfig.StoredPath

	u.proc.regStart = regexp.MustCompile("^[a-zA-Z0-9_].{0,11}$")
	u.proc.regStop = regexp.MustCompile("^/trireme/[a-zA-Z0-9_].{0,11}$")
	u.proc.putoPidMap = cache.NewCache("putoPidMap")
	u.proc.pidToPU = cache.NewCache("pidToPU")

	if uidConfig.EventMetadataExtractor == nil {
		uidConfig.EventMetadataExtractor = MetadataExtractor
	}
	u.proc.metadataExtractor = uidConfig.EventMetadataExtractor
	if u.proc.metadataExtractor == nil {
		return fmt.Errorf("Unable to setup a metadata extractor")
	}

	return nil
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (u *uidMonitor) SetupHandlers(collector collector.EventCollector, puHandler monitorinstance.ProcessingUnitsHandler, syncHandler monitorinstance.SynchronizationHandler) {

	u.proc.collector = collector
	u.proc.puHandler = puHandler
	u.proc.syncHandler = syncHandler
}
