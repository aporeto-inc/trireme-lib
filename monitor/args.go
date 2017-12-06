package monitor

import (
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/cni"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/docker"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/linux"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/uid"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/events"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/processor"
)

// Type specifies the type of monitors supported.
type Type int

// Types supported.
const (
	CNI Type = iota + 1
	Docker
	LinuxProcess
	LinuxHost
	UID
)

// Config specifies the configs for monitors.
type Config struct {
	common    *processor.Config
	mergeTags []string
	monitors  map[Type]interface{}
}

// OptMonitorLinux provides a way to add a linux monitor and related configuration to be used with New().
func OptMonitorLinux(
	host bool,
	extractor events.EventMetadataExtractor,
) func (c *Config) {
	return func(cfg *Config) {
		monCfg := linuxmonitor.DefaultConfig(host)
		monCfg.EventMetadataExtractor = extractor
		if host {
			cfg.monitors[LinuxHost] = monCfg
		}else {
			cfg.monitors[LinuxProcess] = monCfg
		}
	}
}

// OptMonitorCNI provides a way to add a CNI monitor and related configuration to be used with New().
func OptMonitorCNI(
	extractor events.EventMetadataExtractor,
) func (c *Config) {
	return func(cfg *Config) {
		monCfg := cnimonitor.DefaultConfig()
		monCfg.EventMetadataExtractor = extractor
		cfg.monitors[CNI] = monCfg
	}
}

// OptMonitorUID provides a way to add a UID monitor and related configuration to be used with New().
func OptMonitorUID(
	extractor events.EventMetadataExtractor,
) func (c *Config) {
	return func(cfg *Config) {
		monCfg := uidmonitor.DefaultConfig()
		monCfg.EventMetadataExtractor = extractor
		cfg.monitors[UID] = monCfg
	}
}

// OptMonitorDocker provides a way to add a docker monitor and related configuration to be used with New().
func OptMonitorDocker(
	extractor dockermonitor.MetadataExtractor,
	socketType                 string,
	socketAddress              string,
	syncAtStart                bool,
	killContainerOnPolicyError bool,
) func (c *Config) {
	return func(cfg *Config) {
		monCfg := dockermonitor.DefaultConfig()
		monCfg.EventMetadataExtractor = extractor
		monCfg.KillContainerOnPolicyError = killContainerOnPolicyError
		monCfg.SyncAtStart = syncAtStart
		monCfg.SocketType = socketType
		monCfg.SocketAddress = socketAddress
		cfg.monitors[Docker] = monCfg
	}
}

// OptProcessorConfig provides options related to processor configuration to be used with New().
func OptProcessorConfig(
	c collector.EventCollector,
	p processor.ProcessingUnitsHandler,
	s processor.SynchronizationHandler,
	) func (c *Config) {
	if c == nil {
		panic("Collector not provided")
	}
	if p == nil {
		panic("ProcessingUnitsHandler not provided")
	}
	return func(cfg *Config) {
		cfg.common.Collector = c
		cfg.common.PUHandler = p
		cfg.common.SyncHandler = s
	}
}

// OptMergeTags provides a way to add merge tags to be used with New().
func OptMergeTags(tags []string) func(c *Config) {
	return func(c *Config) {
		c.mergeTags = tags
		c.common.MergeTags = tags
	}
}

// New instantiates all/any combination of monitors supported.
func New(opts ...func(*Config)) (Monitor, error) {

	cfg := &Config{}

	// Collect all options
	for _, opt := range opts {
		opt(cfg)
	}

	return setupMonitors(cfg)
}
