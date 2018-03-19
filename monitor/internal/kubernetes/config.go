package kubernetesmonitor

import dockerMonitor "github.com/aporeto-inc/trireme-lib/monitor/internal/docker"

// Config is the config for the Kubernetes monitor
type Config struct {
	DockerConfig dockerMonitor.Config
}
