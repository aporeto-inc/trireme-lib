package monitor

import (
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	cnimonitor "go.aporeto.io/trireme-lib/monitor/internal/cni"
	dockermonitor "go.aporeto.io/trireme-lib/monitor/internal/docker"
	kubernetesmonitor "go.aporeto.io/trireme-lib/monitor/internal/kubernetes"
	linuxmonitor "go.aporeto.io/trireme-lib/monitor/internal/linux"
	podmonitor "go.aporeto.io/trireme-lib/monitor/internal/pod"
	uidmonitor "go.aporeto.io/trireme-lib/monitor/internal/uid"
	"go.aporeto.io/trireme-lib/policy"
)

// Options is provided using functional arguments.
type Options func(*config.MonitorConfig)

// CNIMonitorOption is provided using functional arguments.
type CNIMonitorOption func(*cnimonitor.Config)

// UIDMonitorOption is provided using functional arguments.
type UIDMonitorOption func(*uidmonitor.Config)

// DockerMonitorOption is provided using functional arguments.
type DockerMonitorOption func(*dockermonitor.Config)

// KubernetesMonitorOption is provided using functional arguments.
type KubernetesMonitorOption func(*kubernetesmonitor.Config)

// PodMonitorOption is provided using functional arguments.
type PodMonitorOption func(*podmonitor.Config)

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
	lc := linuxmonitor.DefaultConfig(host, false)
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

// SubOptionMonitorSSHExtractor provides a way to specify metadata extractor for SSH monitors.
func SubOptionMonitorSSHExtractor(extractor extractors.EventMetadataExtractor) LinuxMonitorOption {
	return func(cfg *linuxmonitor.Config) {
		cfg.EventMetadataExtractor = extractor
	}
}

// OptionMonitorSSH provides a way to add a SSH monitor and related configuration to be used with New().
func OptionMonitorSSH(
	opts ...LinuxMonitorOption,
) Options {
	sshc := linuxmonitor.DefaultConfig(false, true)
	// Collect all docker options
	for _, opt := range opts {
		opt(sshc)
	}
	return func(cfg *config.MonitorConfig) {
		cfg.Monitors[config.SSH] = sshc
	}
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

// OptionMonitorKubernetes provides a way to add a docker monitor and related configuration to be used with New().
func OptionMonitorKubernetes(opts ...KubernetesMonitorOption) Options {
	kc := kubernetesmonitor.DefaultConfig()
	// Collect all docker options
	for _, opt := range opts {
		opt(kc)
	}

	return func(cfg *config.MonitorConfig) {
		cfg.Monitors[config.Kubernetes] = kc
	}
}

// SubOptionMonitorKubernetesKubeconfig provides a way to specify a kubeconfig to use to connect to Kubernetes.
// In case of an in-cluter config, leave the kubeconfig field blank
func SubOptionMonitorKubernetesKubeconfig(kubeconfig string) KubernetesMonitorOption {
	return func(cfg *kubernetesmonitor.Config) {
		cfg.Kubeconfig = kubeconfig
	}
}

// SubOptionMonitorKubernetesNodename provides a way to specify the kubernetes node name.
// This is useful for filtering
func SubOptionMonitorKubernetesNodename(nodename string) KubernetesMonitorOption {
	return func(cfg *kubernetesmonitor.Config) {
		cfg.Nodename = nodename
	}
}

// SubOptionMonitorKubernetesHostPod provides a way to specify if we want to activate Pods launched in host mode.
func SubOptionMonitorKubernetesHostPod(enableHostPods bool) KubernetesMonitorOption {
	return func(cfg *kubernetesmonitor.Config) {
		cfg.EnableHostPods = enableHostPods
	}
}

// SubOptionMonitorKubernetesExtractor provides a way to specify metadata extractor for Kubernetes
func SubOptionMonitorKubernetesExtractor(extractor extractors.KubernetesMetadataExtractorType) KubernetesMonitorOption {
	return func(cfg *kubernetesmonitor.Config) {
		cfg.KubernetesExtractor = extractor
	}
}

// SubOptionMonitorKubernetesDockerExtractor provides a way to specify metadata extractor for docker.
func SubOptionMonitorKubernetesDockerExtractor(extractor extractors.DockerMetadataExtractor) KubernetesMonitorOption {
	return func(cfg *kubernetesmonitor.Config) {
		cfg.DockerExtractor = extractor
	}
}

// OptionMonitorPod provides a way to add a Pod monitor and related configuration to be used with New().
func OptionMonitorPod(opts ...PodMonitorOption) Options {
	kc := podmonitor.DefaultConfig()
	// Collect all docker options
	for _, opt := range opts {
		opt(kc)
	}

	return func(cfg *config.MonitorConfig) {
		cfg.Monitors[config.Pod] = kc
	}
}

// SubOptionMonitorPodKubeconfig provides a way to specify a kubeconfig to use to connect to Kubernetes.
// In case of an in-cluter config, leave the kubeconfig field blank
func SubOptionMonitorPodKubeconfig(kubeconfig string) PodMonitorOption {
	return func(cfg *podmonitor.Config) {
		cfg.Kubeconfig = kubeconfig
	}
}

// SubOptionMonitorPodNodename provides a way to specify the kubernetes node name.
// This is useful for filtering
func SubOptionMonitorPodNodename(nodename string) PodMonitorOption {
	return func(cfg *podmonitor.Config) {
		cfg.Nodename = nodename
	}
}

// SubOptionMonitorPodActivateHostPods provides a way to specify if we want to activate Pods launched in host mode.
func SubOptionMonitorPodActivateHostPods(enableHostPods bool) PodMonitorOption {
	return func(cfg *podmonitor.Config) {
		cfg.EnableHostPods = enableHostPods
	}
}

// SubOptionMonitorPodMetadataExtractor provides a way to specify metadata extractor for Kubernetes
func SubOptionMonitorPodMetadataExtractor(extractor extractors.PodMetadataExtractor) PodMonitorOption {
	return func(cfg *podmonitor.Config) {
		cfg.MetadataExtractor = extractor
	}
}

// SubOptionMonitorPodNetclsProgrammer provides a way to program the net_cls cgroup for host network pods in Kubernetes
func SubOptionMonitorPodNetclsProgrammer(netclsprogrammer extractors.PodNetclsProgrammer) PodMonitorOption {
	return func(cfg *podmonitor.Config) {
		cfg.NetclsProgrammer = netclsprogrammer
	}
}

// OptionMergeTags provides a way to add merge tags to be used with New().
func OptionMergeTags(tags []string) Options {
	return func(cfg *config.MonitorConfig) {
		cfg.MergeTags = tags
		cfg.Common.MergeTags = tags
	}
}

// OptionCollector provide a way to add to the docker monitor the collector instance
func OptionCollector(c collector.EventCollector) Options {
	return func(cfg *config.MonitorConfig) {
		cfg.Common.Collector = c
	}
}

// OptionPolicyResolver provides a way to add to the docker monitor the policy resolver instance
func OptionPolicyResolver(p policy.Resolver) Options {
	return func(cfg *config.MonitorConfig) {
		cfg.Common.Policy = p
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
