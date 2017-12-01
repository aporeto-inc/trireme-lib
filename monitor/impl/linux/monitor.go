package linuxmonitor

import (
	"fmt"
	"regexp"

	"github.com/aporeto-inc/trireme-lib/cgnetcls"
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
	StoredPath             string
	ReleasePath            string
}

// linuxMonitor captures all the monitor processor information
// It implements the EventProcessor interface of the rpc monitor
type linuxMonitor struct {
	proc *linuxProcessor
}

// New returns a new implmentation of a monitor implmentation
func New() monitorimpl.Implementation {

	return &linuxMonitor{
		proc: &linuxProcessor{},
	}
}

// Start implements Implementation interface
func (l *linuxMonitor) Start() error {

	if l.proc.collector == nil {
		return fmt.Errorf("Missing configuration: collector")
	}

	if l.proc.syncHandler == nil {
		return fmt.Errorf("Missing configuration: syncHandler")
	}

	if l.proc.puHandler == nil {
		return fmt.Errorf("Missing configuration: puHandler")
	}

	return nil
}

// Stop implements Implementation interface
func (l *linuxMonitor) Stop() error {

	return nil
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (l *linuxMonitor) SetupConfig(registerer processor.Registerer, cfg interface{}) error {

	if cfg == nil {
		cfg = &Config{}
	}

	linuxConfig, ok := cfg.(Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified")
	}

	if registerer != nil {
		registerer.RegisterProcessor(constants.LinuxProcessPU, l.proc)
	}

	if linuxConfig.ReleasePath == "" {
		linuxConfig.ReleasePath = "/var/lib/aporeto/cleaner"
	}

	if linuxConfig.StoredPath == "" {
		linuxConfig.StoredPath = "/var/run/trireme/linux"
	}

	l.proc.netcls = cgnetcls.NewCgroupNetController(linuxConfig.ReleasePath)
	l.proc.contextStore = contextstore.NewFileContextStore(linuxConfig.StoredPath)
	l.proc.storePath = linuxConfig.StoredPath

	l.proc.regStart = regexp.MustCompile("^[a-zA-Z0-9_].{0,11}$")
	l.proc.regStop = regexp.MustCompile("^/trireme/[a-zA-Z0-9_].{0,11}$")

	if linuxConfig.EventMetadataExtractor == nil {
		linuxConfig.EventMetadataExtractor = DefaultHostMetadataExtractor
	}
	l.proc.metadataExtractor = linuxConfig.EventMetadataExtractor
	if l.proc.metadataExtractor == nil {
		return fmt.Errorf("Unable to setup a metadata extractor")
	}

	return nil
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (l *linuxMonitor) SetupHandlers(collector collector.EventCollector, puHandler monitorimpl.ProcessingUnitsHandler, syncHandler monitorimpl.SynchronizationHandler) {

	l.proc.collector = collector
	l.proc.puHandler = puHandler
	l.proc.syncHandler = syncHandler
}
