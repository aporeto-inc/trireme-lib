package trireme

import (
	"github.com/aporeto-inc/trireme-lib/internal/monitor"
	"github.com/aporeto-inc/trireme-lib/internal/monitor/instance/cni"
	"github.com/aporeto-inc/trireme-lib/internal/monitor/instance/docker"
	"github.com/aporeto-inc/trireme-lib/internal/monitor/instance/linux"
	"github.com/aporeto-inc/trireme-lib/internal/monitor/instance/uid"
	"github.com/aporeto-inc/trireme-lib/rpc/events"
	"github.com/aporeto-inc/trireme-lib/rpc/processor"
)

// MonitorOption is provided using functional arguments.
type MonitorOption func(*monitor.Config)

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
) func(*monitor.Config) {
	lc := linuxmonitor.DefaultConfig(host)
	// Collect all docker options
	for _, opt := range opts {
		opt(lc)
	}
	return func(cfg *monitor.Config) {
		if host {
			cfg.Monitors[monitor.LinuxHost] = lc
		} else {
			cfg.Monitors[monitor.LinuxProcess] = lc
		}
	}
}

// OptionMonitorLinuxHost provides a way to add a linux host monitor and related configuration to be used with New().
func OptionMonitorLinuxHost(
	opts ...func(*linuxmonitor.Config),
) func(*monitor.Config) {
	return optionMonitorLinux(true, opts...)
}

// OptionMonitorLinuxProcess provides a way to add a linux process monitor and related configuration to be used with New().
func OptionMonitorLinuxProcess(
	opts ...func(*linuxmonitor.Config),
) func(*monitor.Config) {
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
) func(*monitor.Config) {
	cc := cnimonitor.DefaultConfig()
	// Collect all docker options
	for _, opt := range opts {
		opt(cc)
	}
	return func(cfg *monitor.Config) {
		cfg.Monitors[monitor.CNI] = cc
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
) func(*monitor.Config) {
	uc := uidmonitor.DefaultConfig()
	// Collect all docker options
	for _, opt := range opts {
		opt(uc)
	}
	return func(cfg *monitor.Config) {
		cfg.Monitors[monitor.UID] = uc
	}
}

// SubOptionMonitorDockerExtractor provides a way to specify metadata extractor for docker.
func SubOptionMonitorDockerExtractor(extractor dockermonitor.MetadataExtractor) func(*dockermonitor.Config) {
	return func(cfg *dockermonitor.Config) {
		cfg.EventMetadataExtractor = extractor
	}
}

// SubOptionDockerMonitorMode provides a way to set the mode for docker monitor
func SubOptionDockerMonitorMode(mode int) func(*dockermonitor.Config) {

	return func(cfg *dockermonitor.Config) {
		switch mode {
		case 1:
			cfg.ECS = true
		default:
			cfg.ECS = false
		}

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
func OptionMonitorDocker(opts ...func(*dockermonitor.Config)) func(*monitor.Config) {

	dc := &dockermonitor.Config{}
	// Collect all docker options
	for _, opt := range opts {
		opt(dc)
	}

	return func(cfg *monitor.Config) {
		cfg.Monitors[monitor.Docker] = dc
	}
}

// OptionSynchronizationHandler provides options related to processor configuration to be used with New().
func OptionSynchronizationHandler(
	s processor.SynchronizationHandler,
) func(*monitor.Config) {
	return func(cfg *monitor.Config) {
		cfg.Common.SyncHandler = s
	}
}

// OptionMergeTags provides a way to add merge tags to be used with New().
func OptionMergeTags(tags []string) func(*monitor.Config) {
	return func(cfg *monitor.Config) {
		cfg.MergeTags = tags
		cfg.Common.MergeTags = tags
	}
}

// NewMonitor provides a configuration for monitors.
func NewMonitor(opts ...MonitorOption) *monitor.Config {

	cfg := &monitor.Config{
		Monitors: make(map[monitor.Type]interface{}),
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}
