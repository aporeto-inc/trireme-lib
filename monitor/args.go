package monitor

import (
	"fmt"
	"strings"

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
	common    processor.Config
	MergeTags []string
	monitors  map[Type]interface{}
}

// Option is provided using functional arguments.
type Option func(*Config)

func (c *Config) String() string {
	buf := fmt.Sprintf("MergeTags:[%s] ", strings.Join(c.MergeTags, ","))
	buf += fmt.Sprintf("Common:%+v ", c.common)
	buf += fmt.Sprintf("Monitors:{")
	for k, v := range c.monitors {
		buf += fmt.Sprintf("{%d:%+v},", k, v)
	}
	buf += fmt.Sprintf("}")
	return buf
}

// SubOptionMonitorLinuxExtractor provides a way to specify metadata extractor for linux monitors.
func SubOptionMonitorLinuxExtractor(extractor events.EventMetadataExtractor) func(*linuxmonitor.Config) {
	return func(cfg *linuxmonitor.Config) {
		cfg.EventMetadataExtractor = extractor
	}
}

// optionMonitorLinux provides a way to add a linux monitor and related configuration to be used with New().
func optionMonitorLinux(
	host bool,
	opts ...func(*linuxmonitor.Config),
) func(*Config) {
	lc := linuxmonitor.DefaultConfig(host)
	// Collect all docker options
	for _, opt := range opts {
		opt(lc)
	}
	return func(cfg *Config) {
		if host {
			cfg.monitors[LinuxHost] = lc
		} else {
			cfg.monitors[LinuxProcess] = lc
		}
	}
}

// OptionMonitorLinuxHost provides a way to add a linux host monitor and related configuration to be used with New().
func OptionMonitorLinuxHost(
	opts ...func(*linuxmonitor.Config),
) func(*Config) {
	return optionMonitorLinux(true, opts...)
}

// OptionMonitorLinuxProcess provides a way to add a linux process monitor and related configuration to be used with New().
func OptionMonitorLinuxProcess(
	opts ...func(*linuxmonitor.Config),
) func(*Config) {
	return optionMonitorLinux(false, opts...)
}

// SubOptionMonitorCNIExtractor provides a way to specify metadata extractor for CNI monitors.
func SubOptionMonitorCNIExtractor(extractor events.EventMetadataExtractor) func(*cnimonitor.Config) {
	return func(cfg *cnimonitor.Config) {
		cfg.EventMetadataExtractor = extractor
	}
}

// OptionMonitorCNI provides a way to add a cni monitor and related configuration to be used with New().
func OptionMonitorCNI(
	opts ...func(*cnimonitor.Config),
) func(*Config) {
	cc := cnimonitor.DefaultConfig()
	// Collect all docker options
	for _, opt := range opts {
		opt(cc)
	}
	return func(cfg *Config) {
		cfg.monitors[CNI] = cc
	}
}

// SubOptionMonitorUIDExtractor provides a way to specify metadata extractor for UID monitors.
func SubOptionMonitorUIDExtractor(extractor events.EventMetadataExtractor) func(*uidmonitor.Config) {
	return func(cfg *uidmonitor.Config) {
		cfg.EventMetadataExtractor = extractor
	}
}

// OptionMonitorUID provides a way to add a UID monitor and related configuration to be used with New().
func OptionMonitorUID(
	opts ...func(*uidmonitor.Config),
) func(*Config) {
	uc := uidmonitor.DefaultConfig()
	// Collect all docker options
	for _, opt := range opts {
		opt(uc)
	}
	return func(cfg *Config) {
		cfg.monitors[UID] = uc
	}
}

// SubOptionMonitorDockerExtractor provides a way to specify metadata extractor for docker.
func SubOptionMonitorDockerExtractor(extractor dockermonitor.MetadataExtractor) func(*dockermonitor.Config) {
	return func(cfg *dockermonitor.Config) {
		cfg.EventMetadataExtractor = extractor
	}
}

// SubOptionMonitorDockerSocket provides a way to specify socket info for docker.
func SubOptionMonitorDockerSocket(socketType, socketAddress string) func(*dockermonitor.Config) {
	return func(cfg *dockermonitor.Config) {
		cfg.SocketType = socketType
		cfg.SocketAddress = socketAddress
	}
}

// SubOptionMonitorDockerFlags provides a way to specify configuration flags info for docker.
func SubOptionMonitorDockerFlags(syncAtStart, killContainerOnPolicyError bool) func(*dockermonitor.Config) {
	return func(cfg *dockermonitor.Config) {
		cfg.KillContainerOnPolicyError = killContainerOnPolicyError
		cfg.SyncAtStart = syncAtStart
	}
}

// OptionMonitorDocker provides a way to add a docker monitor and related configuration to be used with New().
func OptionMonitorDocker(opts ...func(*dockermonitor.Config)) func(*Config) {

	dc := &dockermonitor.Config{}
	// Collect all docker options
	for _, opt := range opts {
		opt(dc)
	}

	return func(cfg *Config) {
		cfg.monitors[Docker] = dc
	}
}

// OptionSynchronizationHandler provides options related to processor configuration to be used with New().
func OptionSynchronizationHandler(
	s processor.SynchronizationHandler,
) func(*Config) {
	return func(cfg *Config) {
		cfg.common.SyncHandler = s
	}
}

// OptionMergeTags provides a way to add merge tags to be used with New().
func OptionMergeTags(tags []string) func(*Config) {
	return func(cfg *Config) {
		cfg.MergeTags = tags
		cfg.common.MergeTags = tags
	}
}

// New provides a configuration for monitors.
func New(opts ...Option) *Config {

	cfg := &Config{
		monitors: make(map[Type]interface{}),
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}
