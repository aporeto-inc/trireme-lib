package linuxmonitor

import (
	"fmt"
	"regexp"

	"github.com/aporeto-inc/trireme-lib/cgnetcls"
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
	host                   bool
}

// DefaultConfig provides a default configuration
func DefaultConfig(host bool) *Config {

	if host {
		return &Config{
			EventMetadataExtractor: DefaultHostMetadataExtractor,
			StoredPath:             "/var/run/trireme/host",
			ReleasePath:            "/var/lib/aporeto/cleaner",
			host:                   host,
		}
	}

	return &Config{
		EventMetadataExtractor: DefaultHostMetadataExtractor,
		StoredPath:             "/var/run/trireme/linux",
		ReleasePath:            "/var/lib/aporeto/cleaner",
		host:                   host,
	}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(linuxConfig *Config) *Config {

	defaultConfig := DefaultConfig(false)

	if linuxConfig.ReleasePath == "" {
		linuxConfig.ReleasePath = defaultConfig.ReleasePath
	}

	if linuxConfig.StoredPath == "" {
		linuxConfig.StoredPath = defaultConfig.StoredPath
	}
	if linuxConfig.EventMetadataExtractor == nil {
		linuxConfig.EventMetadataExtractor = defaultConfig.EventMetadataExtractor
	}

	return linuxConfig
}

// linuxMonitor captures all the monitor processor information
// It implements the EventProcessor interface of the rpc monitor
type linuxMonitor struct {
	proc *linuxProcessor
}

// New returns a new implmentation of a monitor implmentation
func New() monitorinstance.Implementation {

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

	if err := l.ReSync(); err != nil {
		return err
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

	defaultConfig := DefaultConfig(false)
	if cfg == nil {
		cfg = defaultConfig
	}

	linuxConfig, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified")
	}

	if registerer != nil {
		registerer.RegisterProcessor(constants.LinuxProcessPU, l.proc)
	}

	// Setup defaults
	linuxConfig = SetupDefaultConfig(linuxConfig)

	// Setup config
	l.proc.host = linuxConfig.host
	l.proc.netcls = cgnetcls.NewCgroupNetController(linuxConfig.ReleasePath)
	l.proc.contextStore = contextstore.NewFileContextStore(linuxConfig.StoredPath)
	l.proc.storePath = linuxConfig.StoredPath

	l.proc.regStart = regexp.MustCompile("^[a-zA-Z0-9_].{0,11}$")
	l.proc.regStop = regexp.MustCompile("^/trireme/[a-zA-Z0-9_].{0,11}$")

	l.proc.metadataExtractor = linuxConfig.EventMetadataExtractor
	if l.proc.metadataExtractor == nil {
		return fmt.Errorf("Unable to setup a metadata extractor")
	}

	return nil
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (l *linuxMonitor) SetupHandlers(m *monitorinstance.Config) {

	l.proc.collector = m.Collector
	l.proc.puHandler = m.PUHandler
	l.proc.syncHandler = m.SyncHandler
	l.proc.mergeTags = m.MergeTags
}

func (l *linuxMonitor) ReSync() error {

	l.proc.ReSync(nil)
	return nil
}
