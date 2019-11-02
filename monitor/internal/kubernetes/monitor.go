package kubernetesmonitor

import (
	"context"
	"fmt"

	"go.aporeto.io/trireme-lib/v11/collector"
	"go.aporeto.io/trireme-lib/v11/monitor/config"
	"go.aporeto.io/trireme-lib/v11/monitor/extractors"
	dockermonitor "go.aporeto.io/trireme-lib/v11/monitor/internal/docker"
	"go.aporeto.io/trireme-lib/v11/monitor/registerer"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	kubecache "k8s.io/client-go/tools/cache"
)

// KubernetesMonitor implements a monitor that sends pod events upstream
// It is implemented as a filter on the standard DockerMonitor.
// It gets all the PU events from the DockerMonitor and if the container is the POD container from Kubernetes,
// It connects to the Kubernetes API and adds the tags that are coming from Kuberntes that cannot be found
type KubernetesMonitor struct {
	dockerMonitor       *dockermonitor.DockerMonitor
	kubeClient          kubernetes.Interface
	localNode           string
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

	// Setting up Kubernetes
	m.localNode = kubernetesconfig.Nodename
	kubeClient, err := NewKubeClient(kubernetesconfig.Kubeconfig)
	if err != nil {
		return fmt.Errorf("kubernetes client instantiation error: %s", err.Error())
	}
	m.kubeClient = kubeClient

	m.enableHostPods = kubernetesconfig.EnableHostPods
	m.kubernetesExtractor = kubernetesconfig.KubernetesExtractor

	m.podStore, m.podController = m.CreateLocalPodController("",
		m.addPod,
		m.deletePod,
		m.updatePod)

	m.podControllerStop = make(chan struct{})

	zap.L().Warn("Using deprecated Kubernetes Monitor")

	return nil
}

// Run starts the monitor.
func (m *KubernetesMonitor) Run(ctx context.Context) error {
	if m.kubeClient == nil {
		return fmt.Errorf("kubernetes client is not initialized correctly")
	}

	// TODO. Give directly the channel to the Kubernetes library
	go m.podController.Run(ctx.Done())
	initialPodSync := make(chan struct{})
	go hasSynced(initialPodSync, m.podController)
	<-initialPodSync

	return m.dockerMonitor.Run(ctx)
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (m *KubernetesMonitor) SetupHandlers(c *config.ProcessorConfig) {
	m.handlers = c
}

// Resync requests to the monitor to do a resync.
func (m *KubernetesMonitor) Resync(ctx context.Context) error {
	return m.dockerMonitor.Resync(ctx)
}
