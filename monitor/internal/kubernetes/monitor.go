package kubernetesmonitor

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	kubecache "k8s.io/client-go/tools/cache"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/monitor/extractors"

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
	dockerMonitor       *dockermonitor.DockerMonitor
	kubernetesClient    *kubernetesclient.Client
	handlers            *config.ProcessorConfig
	cache               *cache
	kubernetesExtractor extractors.KubernetesMetadataExtractorType

	podStore          kubecache.Store
	podController     kubecache.Controller
	podControllerStop chan struct{}

	enableHostPods bool
}

// New returns a new kubernetes monitor.
func New() *KubernetesMonitor {
	kubeMonitor := &KubernetesMonitor{}
	kubeMonitor.cache = newCache()

	return kubeMonitor
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (m *KubernetesMonitor) SetupConfig(registerer registerer.Registerer, cfg interface{}) error {

	defaultConfig := DefaultConfig()

	if cfg == nil {
		cfg = defaultConfig
	}

	kubernetesconfig, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified")
	}

	kubernetesconfig = SetupDefaultConfig(kubernetesconfig)

	processorConfig := &config.ProcessorConfig{
		Policy:    m,
		Collector: collector.NewDefaultCollector(),
	}

	// As the Kubernetes monitor depends on the DockerMonitor, we setup the Docker monitor first
	dockerMon := dockermonitor.New()
	dockerMon.SetupHandlers(processorConfig)

	dockerConfig := dockermonitor.DefaultConfig()
	dockerConfig.EventMetadataExtractor = kubernetesconfig.DockerExtractor

	// we use the defaultconfig for now
	if err := dockerMon.SetupConfig(nil, dockerConfig); err != nil {
		return fmt.Errorf("docker monitor instantiation error: %s", err.Error())
	}

	m.dockerMonitor = dockerMon

	kubernetesClient, err := kubernetesclient.NewClient(kubernetesconfig.Kubeconfig, kubernetesconfig.Nodename)
	if err != nil {
		return fmt.Errorf("kubernetes client instantiation error: %s", err.Error())
	}
	m.kubernetesClient = kubernetesClient
	m.enableHostPods = kubernetesconfig.EnableHostPods
	m.kubernetesExtractor = kubernetesconfig.KubernetesExtractor

	m.podStore, m.podController = m.kubernetesClient.CreateLocalPodController("",
		m.addPod,
		m.deletePod,
		m.updatePod)

	m.podControllerStop = make(chan struct{})

	zap.L().Debug("Pod Controller created")

	return nil
}

// Run starts the monitor.
func (m *KubernetesMonitor) Run(ctx context.Context) error {
	if m.kubernetesClient == nil {
		return fmt.Errorf("kubernetes client is not initialized correctly")
	}

	go m.podController.Run(m.podControllerStop)
	initialPodSync := make(chan struct{})
	go hasSynced(initialPodSync, m.podController)
	<-initialPodSync

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
	// TODO: Redifine this interface ?
	return nil
}

// ReSync ???
func (m *KubernetesMonitor) ReSync(ctx context.Context) error {
	return m.dockerMonitor.ReSync(ctx)
}
