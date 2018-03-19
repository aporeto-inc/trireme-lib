package kubernetesmonitor

import dockerMonitor "github.com/aporeto-inc/trireme-lib/monitor/internal/docker"

// Config is the config for the Kubernetes monitor
type Config struct {
	DockerConfig dockerMonitor.Config
}

// DefaultConfig provides a default configuration
func DefaultConfig() *Config {
	return &Config{}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(dockerConfig *Config) *Config {
	return DefaultConfig()
}
