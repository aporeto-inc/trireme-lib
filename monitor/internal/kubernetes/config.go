package kubernetesmonitor

import (
	"github.com/aporeto-inc/trireme-lib/monitor/extractors"
	dockerMonitor "github.com/aporeto-inc/trireme-lib/monitor/internal/docker"
)

// Config is the config for the Kubernetes monitor
type Config struct {
	DockerConfig dockerMonitor.Config

	Kubeconfig             string
	Nodename               string
	EventMetadataExtractor extractors.KubernetesMetadataExtractorType

	EnableHostPods bool
}

// DefaultConfig provides a default configuration
func DefaultConfig() *Config {
	return &Config{
		EventMetadataExtractor: extractors.DefaultKubernetesMetadataExtractor,
		EnableHostPods:         false,
		Kubeconfig:             "",
		Nodename:               "",
	}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(kubernetesConfig *Config) *Config {
	return kubernetesConfig
}
