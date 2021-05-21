package monitor

import (
	"sync"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/config"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/external"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/extractors"
	dockermonitor "go.aporeto.io/enforcerd/trireme-lib/monitor/internal/docker"
	k8smonitor "go.aporeto.io/enforcerd/trireme-lib/monitor/internal/k8s"
	linuxmonitor "go.aporeto.io/enforcerd/trireme-lib/monitor/internal/linux"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	criapi "k8s.io/cri-api/pkg/apis"
)

// Options is provided using functional arguments.
type Options func(*config.MonitorConfig)

// DockerMonitorOption is provided using functional arguments.
type DockerMonitorOption func(*dockermonitor.Config)

// K8smonitorOption is provided using functional arguments.
type K8smonitorOption func(*k8smonitor.Config)

// LinuxMonitorOption is provided using functional arguments.
type LinuxMonitorOption func(*linuxmonitor.Config)

// SubOptionMonitorLinuxExtractor provides a way to specify metadata extractor for linux monitors.
func SubOptionMonitorLinuxExtractor(extractor extractors.EventMetadataExtractor) LinuxMonitorOption {
	return func(cfg *linuxmonitor.Config) {
		cfg.EventMetadataExtractor = extractor
	}
}

// SubOptionMonitorLinuxRealeaseAgentPath specifies the path to release agent programmed in cgroup
func SubOptionMonitorLinuxRealeaseAgentPath(releasePath string) LinuxMonitorOption {
	return func(cfg *linuxmonitor.Config) {
		cfg.ReleasePath = releasePath
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

// SubOptionMonitorDockerExtractor provides a way to specify metadata extractor for docker.
func SubOptionMonitorDockerExtractor(extractor extractors.DockerMetadataExtractor) DockerMonitorOption {
	return func(cfg *dockermonitor.Config) {
		cfg.EventMetadataExtractor = extractor
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
func SubOptionMonitorDockerFlags(syncAtStart bool) DockerMonitorOption {
	return func(cfg *dockermonitor.Config) {
		cfg.SyncAtStart = syncAtStart
	}
}

// SubOptionMonitorDockerDestroyStoppedContainers sets the option to destroy stopped containers.
func SubOptionMonitorDockerDestroyStoppedContainers(f bool) DockerMonitorOption {
	return func(cfg *dockermonitor.Config) {
		cfg.DestroyStoppedContainers = f
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

// OptionMonitorK8s provides a way to add a K8s monitor and related configuration to be used with New().
func OptionMonitorK8s(opts ...K8smonitorOption) Options {
	kc := k8smonitor.DefaultConfig()
	for _, opt := range opts {
		opt(kc)
	}

	return func(cfg *config.MonitorConfig) {
		cfg.Monitors[config.K8s] = kc
	}
}

// SubOptionMonitorK8sKubeconfig provides a way to specify a kubeconfig to use to connect to Kubernetes.
// In case of an in-cluter config, leave the kubeconfig field blank
func SubOptionMonitorK8sKubeconfig(kubeconfig string) K8smonitorOption {
	return func(cfg *k8smonitor.Config) {
		cfg.Kubeconfig = kubeconfig
	}
}

// SubOptionMonitorK8sNodename provides a way to specify the kubernetes node name.
// This is useful for filtering
func SubOptionMonitorK8sNodename(nodename string) K8smonitorOption {
	return func(cfg *k8smonitor.Config) {
		cfg.Nodename = nodename
	}
}

// SubOptionMonitorK8sMetadataExtractor provides a way to specify metadata extractor for Kubernetes
func SubOptionMonitorK8sMetadataExtractor(extractor extractors.PodMetadataExtractor) K8smonitorOption {
	return func(cfg *k8smonitor.Config) {
		cfg.MetadataExtractor = extractor
	}
}

// SubOptionMonitorK8sCRIRuntimeService provides a way to pass through the CRI runtime service
func SubOptionMonitorK8sCRIRuntimeService(criRuntimeService criapi.RuntimeService) K8smonitorOption {
	return func(cfg *k8smonitor.Config) {
		cfg.CRIRuntimeService = criRuntimeService
	}
}

// OptionMergeTags provides a way to add merge tags to be used with New().
func OptionMergeTags(tags []string) Options {
	return func(cfg *config.MonitorConfig) {
		cfg.MergeTags = tags
		cfg.Common.MergeTags = tags
	}
}

// OptionCollector provide a way to add to the monitor the collector instance
func OptionCollector(c collector.EventCollector) Options {
	return func(cfg *config.MonitorConfig) {
		cfg.Common.Collector = c
	}
}

// OptionPolicyResolver provides a way to add to the monitor the policy resolver instance
func OptionPolicyResolver(p policy.Resolver) Options {
	return func(cfg *config.MonitorConfig) {
		cfg.Common.Policy = p
	}
}

// OptionExternalEventSenders provide a way to add to the monitor the external event senders
func OptionExternalEventSenders(evs []external.ReceiverRegistration) Options {
	return func(cfg *config.MonitorConfig) {
		cfg.Common.ExternalEventSender = evs
	}
}

// OptionResyncLock provide a shared lock between monitors if the monitor desires to sync with other components during PU resync at startup
func OptionResyncLock(resyncLock *sync.RWMutex) Options {
	return func(cfg *config.MonitorConfig) {
		cfg.Common.ResyncLock = resyncLock
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
