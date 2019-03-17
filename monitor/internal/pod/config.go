package podmonitor

import (
	"go.aporeto.io/trireme-lib/monitor/extractors"
)

// Config is the config for the Kubernetes monitor
type Config struct { // nolint
	Kubeconfig     string
	Nodename       string
	EnableHostPods bool

	MetadataExtractor extractors.PodMetadataExtractor
	NetclsProgrammer  extractors.PodNetclsProgrammer
}

// DefaultConfig provides a default configuration
func DefaultConfig() *Config {
	return &Config{
		MetadataExtractor: nil,
		NetclsProgrammer:  nil,
		EnableHostPods:    false,
		Kubeconfig:        "",
		Nodename:          "",
	}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(kubernetesConfig *Config) *Config {
	return kubernetesConfig
}
