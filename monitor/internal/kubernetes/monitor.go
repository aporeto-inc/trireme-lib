package kubernetesmonitor

import (
	"context"
	"fmt"

	"github.com/aporeto-inc/trireme-lib/monitor/config"
	"github.com/aporeto-inc/trireme-lib/monitor/registerer"

	kubernetesclient "github.com/aporeto-inc/trireme-kubernetes/kubernetes"
	dockermonitor "github.com/aporeto-inc/trireme-lib/monitor/internal/docker"
)

// KubernetesMonitor implements a monitor that sends pod events upstream
// It is implemented as a filter on the standard DockerMonitor.
// It gets all the PU events from the DockerMonitor and if the container is the POD container from Kubernetes,
// It connects to the Kubernetes API and adds the tags that are coming from Kuberntes that cannot be found
type KubernetesMonitor struct {
	dockerMonitor    *dockermonitor.DockerMonitor
	kubernetesClient *kubernetesclient.Client
	handlers         *config.ProcessorConfig
}

// New returns a new kubernetes monitor.
func New() *KubernetesMonitor {
	kubeMonitor := &KubernetesMonitor{}

	return kubeMonitor
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (m *KubernetesMonitor) SetupConfig(registerer registerer.Registerer, cfg interface{}) error {
	processorConfig := &config.ProcessorConfig{
		Policy: m,
	}

	// As the Kubernetes monitor depends on the DockerMonitor, we setup the Docker monitor first
	dockerMon := dockermonitor.New()
	dockerMon.SetupHandlers(processorConfig)

	// we use the defaultconfig for now
	if err := dockerMon.SetupConfig(nil, nil); err != nil {
		return fmt.Errorf("DockerMonitor instantiation error: %s", err.Error())
	}

	m.dockerMonitor = dockerMon

	return nil
}

// Run starts the monitor.
func (m *KubernetesMonitor) Run(ctx context.Context) error {
	return m.dockerMonitor.Run(ctx)
}

// UpdateConfiguration updates the configuration of the monitor
func (m *KubernetesMonitor) UpdateConfiguration(ctx context.Context, config *config.MonitorConfig) error {
	// TODO: implement this
	return nil
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (m *KubernetesMonitor) SetupHandlers(c *config.ProcessorConfig) {
	m.handlers = c
}

// Resync requests to the monitor to do a resync.
func (m *KubernetesMonitor) Resync(ctx context.Context) error {
	// TODO: implement this
	return nil
}
