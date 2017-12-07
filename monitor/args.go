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

// OptMonitorLinuxExtractor provides a way to specify metadata extractor for linux monitors.
func OptMonitorLinuxExtractor(extractor events.EventMetadataExtractor) func (c *linuxmonitor.Config) {
	return func(c *linuxmonitor.Config) {
		c.EventMetadataExtractor = extractor
	}
}

// OptMonitorLinux provides a way to add a linux monitor and related configuration to be used with New().
func OptMonitorLinux(
	host bool,
	opts ...func(*linuxmonitor.Config),
) func (c *Config) {
	lc := linuxmonitor.DefaultConfig(host)
	// Collect all docker options
	for _, opt := range opts {
		opt(lc)
	}
	return func(cfg *Config) {
		if host {
			cfg.monitors[LinuxHost] = lc
		}else {
			cfg.monitors[LinuxProcess] = lc
		}
	}
}

// OptMonitorCNIExtractor provides a way to specify metadata extractor for CNI monitors.
func OptMonitorCNIExtractor(extractor events.EventMetadataExtractor) func (c *cnimonitor.Config) {
	return func(c *cnimonitor.Config) {
		c.EventMetadataExtractor = extractor
	}
}

// OptMonitorCNI provides a way to add a cni monitor and related configuration to be used with New().
func OptMonitorCNI(
	opts ...func(*cnimonitor.Config),
) func (c *Config) {
	cc := cnimonitor.DefaultConfig()
	// Collect all docker options
	for _, opt := range opts {
		opt(cc)
	}
	return func(cfg *Config) {
		cfg.monitors[CNI] = cc
	}
}

// OptMonitorUIDExtractor provides a way to specify metadata extractor for UID monitors.
func OptMonitorUIDExtractor(extractor events.EventMetadataExtractor) func (c *uidmonitor.Config) {
	return func(c *uidmonitor.Config) {
		c.EventMetadataExtractor = extractor
	}
}

// OptMonitorUID provides a way to add a UID monitor and related configuration to be used with New().
func OptMonitorUID(
	opts ...func(*uidmonitor.Config),
) func (c *Config) {
	uc := uidmonitor.DefaultConfig()
	// Collect all docker options
	for _, opt := range opts {
		opt(uc)
	}
	return func(cfg *Config) {
		cfg.monitors[UID] = uc
	}
}

// OptMonitorDockerExtractor provides a way to specify metadata extractor for docker.
func OptMonitorDockerExtractor(extractor dockermonitor.MetadataExtractor) func (c *dockermonitor.Config) {
	return func(c *dockermonitor.Config) {
		c.EventMetadataExtractor = extractor
	}
}

// OptMonitorDockerSocket provides a way to specify socket info for docker.
func OptMonitorDockerSocket(socketType, socketAddress string) func (c *dockermonitor.Config) {
	return func(c *dockermonitor.Config) {
		c.SocketType = socketType
		c.SocketAddress = socketAddress
	}
}

// OptMonitorDockerFlags provides a way to specify configuration flags info for docker.
func OptMonitorDockerFlags(syncAtStart, killContainerOnPolicyError bool) func (c *dockermonitor.Config) {
	return func(c *dockermonitor.Config) {
		c.KillContainerOnPolicyError = killContainerOnPolicyError
		c.SyncAtStart = syncAtStart
	}
}

// OptMonitorDocker provides a way to add a docker monitor and related configuration to be used with New().
func OptMonitorDocker(opts ...func(*dockermonitor.Config)) func (c *Config) {

	dc := &dockermonitor.Config{}
	// Collect all docker options
	for _, opt := range opts {
		opt(dc)
	}

	return func(cfg *Config) {
		cfg.monitors[Docker] = dc
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

// SetupConfig provides a configuration for monitors
func SetupConfig(opts ...func(*Config)) *Config {

	cfg := &Config{}

	// Collect all options
	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}

// New instantiates all/any combination of monitors supported.
func New(opts ...func(*Config)) (Monitor, error) {
	return NewMonitors(SetupConfig(opts...))
}
