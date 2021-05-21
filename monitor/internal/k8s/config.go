package k8smonitor

import (
	criapi "k8s.io/cri-api/pkg/apis"

	"go.aporeto.io/enforcerd/trireme-lib/monitor/extractors"
)

// Config is the config for the Kubernetes monitor
type Config struct { // nolint
	Kubeconfig string
	Nodename   string

	CRIRuntimeService criapi.RuntimeService

	MetadataExtractor extractors.PodMetadataExtractor
}

// DefaultConfig provides a default configuration
func DefaultConfig() *Config {
	return &Config{
		MetadataExtractor: nil,
		CRIRuntimeService: nil,
		Kubeconfig:        "",
		Nodename:          "",
	}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(kubernetesConfig *Config) *Config {
	return kubernetesConfig
}
