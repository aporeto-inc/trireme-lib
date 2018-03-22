package kubernetesmonitor

import dockerMonitor "github.com/aporeto-inc/trireme-lib/monitor/internal/docker"

// Config is the config for the Kubernetes monitor
type Config struct {
	DockerConfig dockerMonitor.Config

	EnableHostPods bool
	Kubeconfig     string
	Nodename       string
}

// DefaultConfig provides a default configuration
func DefaultConfig() *Config {
	return &Config{
		EnableHostPods: false,
		Kubeconfig:     "",
		Nodename:       "",
	}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(kubernetesConfig *Config) *Config {
	return kubernetesConfig
}
