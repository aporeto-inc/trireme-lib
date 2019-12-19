package podmonitor

import (
	"go.aporeto.io/trireme-lib/monitor/extractors"
)

// Config is the config for the Kubernetes monitor
type Config struct { // nolint
	Kubeconfig     string
	Nodename       string
	EnableHostPods bool
	Workers        int

	MetadataExtractor         extractors.PodMetadataExtractor
	NetclsProgrammer          extractors.PodNetclsProgrammer
	PidsSetMaxProcsProgrammer extractors.PodPidsSetMaxProcsProgrammer
	ResetNetcls               extractors.ResetNetclsKubepods
	SandboxExtractor          extractors.PodSandboxExtractor
}

// DefaultConfig provides a default configuration
func DefaultConfig() *Config {
	return &Config{
		MetadataExtractor:         nil,
		NetclsProgrammer:          nil,
		PidsSetMaxProcsProgrammer: nil,
		ResetNetcls:               nil,
		SandboxExtractor:          nil,
		EnableHostPods:            false,
		Kubeconfig:                "",
		Nodename:                  "",
		Workers:                   4,
	}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(kubernetesConfig *Config) *Config {
	return kubernetesConfig
}
