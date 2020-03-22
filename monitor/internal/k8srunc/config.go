package k8sruncmonitor

import (
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/utils/cri"
)

// Config is the config for the Kubernetes monitor
type Config struct { // nolint
	Kubeconfig string
	Nodename   string

	CRIRuntimeService cri.ExtendedRuntimeService

	MetadataExtractor extractors.PodMetadataExtractor
	NetclsProgrammer  extractors.PodNetclsProgrammer
	ResetNetcls       extractors.ResetNetclsKubepods
}

// DefaultConfig provides a default configuration
func DefaultConfig() *Config {
	return &Config{
		MetadataExtractor: nil,
		NetclsProgrammer:  nil,
		ResetNetcls:       nil,
		CRIRuntimeService: nil,
		Kubeconfig:        "",
		Nodename:          "",
	}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(kubernetesConfig *Config) *Config {
	return kubernetesConfig
}
