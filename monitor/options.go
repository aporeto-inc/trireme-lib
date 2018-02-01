package monitor

import (
	"github.com/aporeto-inc/trireme-lib/monitor/config"
	"github.com/aporeto-inc/trireme-lib/monitor/constants"
	"github.com/aporeto-inc/trireme-lib/monitor/extractors"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/cni"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/docker"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/linux"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/uid"
)

// Options is provided using functional arguments.
type Options func(*config.MonitorConfig)

// CNIMonitorOption is provided using functional arguments.
type CNIMonitorOption func(*cnimonitor.Config)

// UIDMonitorOption is provided using functional arguments.
type UIDMonitorOption func(*uidmonitor.Config)

// DockerMonitorOption is provided using functional arguments.
type DockerMonitorOption func(*dockermonitor.Config)

// LinuxMonitorOption is provided using functional arguments.
type LinuxMonitorOption func(*linuxmonitor.Config)

// SubOptionMonitorLinuxExtractor provides a way to specify metadata extractor for linux monitors.
func SubOptionMonitorLinuxExtractor(extractor extractors.EventMetadataExtractor) LinuxMonitorOption {
	return func(cfg *linuxmonitor.Config) {
		cfg.EventMetadataExtractor = extractor
	}
}

// optionMonitorLinux provides a way to add a linux monitor and related configuration to be used with New().
func optionMonitorLinux(
	host bool,
	opts ...LinuxMonitorOption,
) Options {
	lc := linuxmonitor.DefaultConfig(host)
	// Collect all docker options
	for _, opt := range opts {
		opt(lc)
	}
	return func(cfg *config.MonitorConfig) {
		if host {
			cfg.Monitors[config.LinuxHost] = lc
		} else {
			cfg.Monitors[config.LinuxProcess] = lc
		}
	}
}

// OptionMonitorLinuxHost provides a way to add a linux host monitor and related configuration to be used with New().
func OptionMonitorLinuxHost(
	opts ...LinuxMonitorOption,
) Options {
	return optionMonitorLinux(true, opts...)
}

// OptionMonitorLinuxProcess provides a way to add a linux process monitor and related configuration to be used with New().
func OptionMonitorLinuxProcess(
	opts ...LinuxMonitorOption,
) Options {
	return optionMonitorLinux(false, opts...)
}

// SubOptionMonitorCNIExtractor provides a way to specify metadata extractor for CNI monitors.
func SubOptionMonitorCNIExtractor(extractor extractors.EventMetadataExtractor) CNIMonitorOption {
	return func(cfg *cnimonitor.Config) {
		cfg.EventMetadataExtractor = extractor
	}
}

// OptionMonitorCNI provides a way to add a cni monitor and related configuration to be used with New().
func OptionMonitorCNI(
	opts ...CNIMonitorOption,
) Options {
	cc := cnimonitor.DefaultConfig()
	// Collect all docker options
	for _, opt := range opts {
		opt(cc)
	}
	return func(cfg *config.MonitorConfig) {
		cfg.Monitors[config.CNI] = cc
	}
}

// SubOptionMonitorUIDExtractor provides a way to specify metadata extractor for UID monitors.
func SubOptionMonitorUIDExtractor(extractor extractors.EventMetadataExtractor) UIDMonitorOption {
	return func(cfg *uidmonitor.Config) {
		cfg.EventMetadataExtractor = extractor
	}
}

// OptionMonitorUID provides a way to add a UID monitor and related configuration to be used with New().
func OptionMonitorUID(
	opts ...UIDMonitorOption,
) Options {
	uc := uidmonitor.DefaultConfig()
	// Collect all docker options
	for _, opt := range opts {
		opt(uc)
	}
	return func(cfg *config.MonitorConfig) {
		cfg.Monitors[config.UID] = uc
	}
}

// SubOptionMonitorDockerExtractor provides a way to specify metadata extractor for docker.
func SubOptionMonitorDockerExtractor(extractor extractors.DockerMetadataExtractor) DockerMonitorOption {
	return func(cfg *dockermonitor.Config) {
		cfg.EventMetadataExtractor = extractor
	}
}

// SubOptionDockerMonitorMode provides a way to set the mode for docker monitor
func SubOptionDockerMonitorMode(mode constants.DockerMonitorMode) DockerMonitorOption {

	return func(cfg *dockermonitor.Config) {
		switch mode {
		case constants.DockerMode:
		case constants.KubernetesMode:
			cfg.NoProxyMode = false
		case constants.NoProxyMode:
			cfg.NoProxyMode = true
		default:
			cfg.NoProxyMode = false
		}

	}

}

// SubOptionMonitorDockerSocket provides a way to specify socket info for docker.
func SubOptionMonitorDockerSocket(socketType, socketAddress string) DockerMonitorOption {
	return func(cfg *dockermonitor.Config) {
		cfg.SocketType = socketType
		cfg.SocketAddress = socketAddress
	}
}

// SubOptionMonitorDockerFlags provides a way to specify configuration flags info for docker.
func SubOptionMonitorDockerFlags(syncAtStart, killContainerOnPolicyError bool) DockerMonitorOption {
	return func(cfg *dockermonitor.Config) {
		cfg.KillContainerOnPolicyError = killContainerOnPolicyError
		cfg.SyncAtStart = syncAtStart
	}
}

// OptionMonitorDocker provides a way to add a docker monitor and related configuration to be used with New().
func OptionMonitorDocker(opts ...DockerMonitorOption) Options {

	dc := dockermonitor.DefaultConfig()
	// Collect all docker options
	for _, opt := range opts {
		opt(dc)
	}

	return func(cfg *config.MonitorConfig) {
		cfg.Monitors[config.Docker] = dc
	}
}

// OptionMergeTags provides a way to add merge tags to be used with New().
func OptionMergeTags(tags []string) Options {
	return func(cfg *config.MonitorConfig) {
		cfg.MergeTags = tags
		cfg.Common.MergeTags = tags
	}
}

// NewMonitor provides a configuration for monitors.
func NewMonitor(opts ...Options) *config.MonitorConfig {

	cfg := &config.MonitorConfig{
		Monitors: make(map[config.Type]interface{}),
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}
