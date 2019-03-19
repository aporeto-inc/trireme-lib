package podmonitor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/monitor/registerer"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// PodMonitor implements a monitor that sends pod events upstream
// It is implemented as a filter on the standard DockerMonitor.
// It gets all the PU events from the DockerMonitor and if the container is the POD container from Kubernetes,
// It connects to the Kubernetes API and adds the tags that are coming from Kuberntes that cannot be found
type PodMonitor struct {
	localNode         string
	handlers          *config.ProcessorConfig
	metadataExtractor extractors.PodMetadataExtractor
	netclsProgrammer  extractors.PodNetclsProgrammer
	enableHostPods    bool
	kubeCfg           *rest.Config
	kubeClient        client.Client
	eventsCh          chan event.GenericEvent
}

// New returns a new kubernetes monitor.
func New() *PodMonitor {
	podMonitor := &PodMonitor{
		eventsCh: make(chan event.GenericEvent),
	}

	return podMonitor
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (m *PodMonitor) SetupConfig(registerer registerer.Registerer, cfg interface{}) error {

	defaultConfig := DefaultConfig()

	if cfg == nil {
		cfg = defaultConfig
	}

	kubernetesconfig, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified (type '%T')", cfg)
	}

	kubernetesconfig = SetupDefaultConfig(kubernetesconfig)

	// build kubernetes config
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

	if kubernetesconfig.MetadataExtractor == nil {
		return fmt.Errorf("missing metadata extractor")
	}

	if kubernetesconfig.NetclsProgrammer == nil {
		return fmt.Errorf("missing net_cls programmer")
	}

	// Setting up Kubernetes
	m.kubeCfg = kubeCfg
	m.localNode = kubernetesconfig.Nodename
	m.enableHostPods = kubernetesconfig.EnableHostPods
	m.metadataExtractor = kubernetesconfig.MetadataExtractor
	m.netclsProgrammer = kubernetesconfig.NetclsProgrammer

	return nil
}

// Run starts the monitor.
func (m *PodMonitor) Run(ctx context.Context) error {
	if m.kubeCfg == nil {
		return errors.New("pod: missing kubeconfig")
	}

	if err := m.handlers.IsComplete(); err != nil {
		return fmt.Errorf("pod: %s", err.Error())
	}

	mgr, err := manager.New(m.kubeCfg, manager.Options{})
	if err != nil {
		return fmt.Errorf("pod: %s", err.Error())
	}

	r := newReconciler(mgr, m.handlers, m.metadataExtractor, m.netclsProgrammer, m.localNode, m.enableHostPods)
	if err := addController(mgr, r, m.eventsCh); err != nil {
		return fmt.Errorf("pod: %s", err.Error())
	}

	controllerStarted := make(chan struct{})
	if err := mgr.Add(&runnable{ch: controllerStarted}); err != nil {
		return fmt.Errorf("pod: %s", err.Error())
	}

	// starting the manager is a bit awkward:
	// - it does not use contexts
	// - we pass in a fake signal handler channel
	// - we start another go routine which waits for the context to be cancelled
	//   and closes that channel if that is the case
	// -
	z := make(chan struct{})
	errCh := make(chan error, 2)
	go func() {
		<-ctx.Done()
		close(z)
		errCh <- ctx.Err()
	}()
	go func() {
		if err := mgr.Start(z); err != nil {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("pod: %s", err.Error())
	case <-time.After(5 * time.Second):
		// we give the controller 5 seconds to report back
		return errors.New("pod: controller did not start within 5s")
	case <-controllerStarted:
		m.kubeClient = mgr.GetClient()
		return nil
	}
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (m *PodMonitor) SetupHandlers(c *config.ProcessorConfig) {
	m.handlers = c
}

// Resync requests to the monitor to do a resync.
func (m *PodMonitor) Resync(ctx context.Context) error {
	if m.kubeClient == nil {
		return errors.New("pod: client has not been initialized yet")
	}

	return ResyncWithAllPods(ctx, m.kubeClient, m.eventsCh)
}

type runnable struct {
	ch chan struct{}
}

func (r *runnable) Start(z <-chan struct{}) error {
	// close the indicator channel which means that the manager has been started successfully
	close(r.ch)

	// stay up and running, the manager needs that
	<-z
	return nil
}
