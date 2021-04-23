package k8smonitor

import (
	"context"
	"errors"
	"fmt"
	"sync"

	criapi "k8s.io/cri-api/pkg/apis"

	"go.aporeto.io/enforcerd/internal/extractors/containermetadata"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/config"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/constants"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/extractors"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/registerer"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// K8sMonitor is the monitor for Kubernetes.
type K8sMonitor struct {
	nodename                         string
	handlers                         *config.ProcessorConfig
	metadataExtractor                extractors.PodMetadataExtractor
	kubeClient                       kubernetes.Interface
	podLister                        listersv1.PodLister
	criRuntimeService                criapi.RuntimeService
	podCache                         podCacheInterface
	runtimeCache                     runtimeCacheInterface
	startEventRetry                  startEventRetryFunc
	cniInstalledOrRuncProxyStartedCh chan struct{}
	cniInstalledOrRuncProxyStarted   bool
	extMonitorStartedLock            sync.RWMutex
}

// New returns a new kubernetes monitor.
func New(ctx context.Context) *K8sMonitor {
	m := &K8sMonitor{}
	m.podCache = newPodCache(m.updateEvent)
	m.runtimeCache = newRuntimeCache(ctx, m.stopEvent)
	m.cniInstalledOrRuncProxyStartedCh = make(chan struct{})
	return m
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (m *K8sMonitor) SetupConfig(_ registerer.Registerer, cfg interface{}) error {

	defaultConfig := DefaultConfig()

	if cfg == nil {
		cfg = defaultConfig
	}

	kubernetesconfig, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified (type '%T')", cfg)
	}

	kubernetesconfig = SetupDefaultConfig(kubernetesconfig)

	// simple config checks
	if kubernetesconfig.MetadataExtractor == nil {
		return fmt.Errorf("missing metadata extractor")
	}
	if kubernetesconfig.CRIRuntimeService == nil {
		return fmt.Errorf("missing CRIRuntimeService implementation")
	}

	// Initialize most of our monitor
	m.nodename = kubernetesconfig.Nodename
	m.metadataExtractor = kubernetesconfig.MetadataExtractor
	m.criRuntimeService = kubernetesconfig.CRIRuntimeService

	// build kubernetes client config
	var kubeCfg *rest.Config
	if len(kubernetesconfig.Kubeconfig) > 0 {
		var err error
		kubeCfg, err = clientcmd.BuildConfigFromFlags("", kubernetesconfig.Kubeconfig)
		if err != nil {
			return err
		}
	} else {
		var err error
		kubeCfg, err = rest.InClusterConfig()
		if err != nil {
			return err
		}
	}

	// and initialize client from it
	var err error
	m.kubeClient, err = kubernetes.NewForConfig(kubeCfg)
	return err
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (m *K8sMonitor) SetupHandlers(c *config.ProcessorConfig) {
	m.handlers = c
}

// Run starts the monitor implementation.
func (m *K8sMonitor) Run(ctx context.Context) error {
	m.startEventRetry = newStartEventRetryFunc(ctx, containermetadata.AutoDetect(), m.startEvent)
	if m.kubeClient == nil {
		return errors.New("K8sMonitor: missing Kubernetes client")
	}

	if err := m.handlers.IsComplete(); err != nil {
		return fmt.Errorf("K8sMonitor: handlers are not complete: %s", err.Error())
	}

	if m.handlers.ExternalEventSender == nil {
		return fmt.Errorf("K8sMonitor: external event sender option must be used together with this monitor")
	}

	// setup informer for update events (this starts the informer as well)
	// this also returns a pod lister which uses the same underlying cache as the informer
	m.podLister = m.podCache.SetupInformer(ctx, m.kubeClient, m.nodename, defaultNeedsUpdate)

	// register ourselves with the gRPC server to receive events
	var registered bool
	for _, evs := range m.handlers.ExternalEventSender {
		if evs.SenderName() == constants.MonitorExtSenderName {
			if err := evs.Register(constants.K8sMonitorRegistrationName, m); err != nil {
				return fmt.Errorf("K8sMonitor: failed to register with the grpcMonitorServer external events sender: %w", err)
			}
			registered = true
			break
		}
	}
	if !registered {
		return fmt.Errorf("K8sMonitor: failed to register with the grpcMonitorServer external events sender: unavailable")
	}

	// get list of pods on node, and handle them
	if err := m.onStartup(ctx, m.startEvent); err != nil {
		return fmt.Errorf("K8sMonitor: failed to get list of pods running sandboxes from CRI and generating events for them: %s", err)
	}

	return nil
}

// Resync should resynchronize PUs. This should be done while starting up.
func (m *K8sMonitor) Resync(ctx context.Context) error {
	return nil
}
