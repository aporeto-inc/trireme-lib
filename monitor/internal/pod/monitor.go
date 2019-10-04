package podmonitor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	cripleg "go.aporeto.io/trireme-lib/monitor/internal/pod/internal/pleg"
	"go.aporeto.io/trireme-lib/monitor/internal/pod/internal/queue"
	"go.aporeto.io/trireme-lib/monitor/registerer"
	"go.aporeto.io/trireme-lib/utils/cri"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/go-logr/zapr"
)

const (
	criClientVersion string = "v1alpha2"
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
	resetNetcls       extractors.ResetNetclsKubepods
	sandboxExtractor  extractors.PodSandboxExtractor
	enableHostPods    bool
	workers           int
	kubeCfg           *rest.Config
	kubeClient        client.Client
	eventsCh          chan event.GenericEvent
	criRuntimeService cri.ExtendedRuntimeService
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

	monitorconfig, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified (type '%T')", cfg)
	}

	monitorconfig = SetupDefaultConfig(monitorconfig)

	// build kubernetes config
	var kubeCfg *rest.Config
	if len(monitorconfig.Kubeconfig) > 0 {
		var err error
		kubeCfg, err = clientcmd.BuildConfigFromFlags("", monitorconfig.Kubeconfig)
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

	if monitorconfig.MetadataExtractor == nil {
		return fmt.Errorf("missing metadata extractor")
	}

	if monitorconfig.NetclsProgrammer == nil {
		return fmt.Errorf("missing net_cls programmer")
	}

	if monitorconfig.ResetNetcls == nil {
		return fmt.Errorf("missing reset net_cls implementation")
	}
	if monitorconfig.SandboxExtractor == nil {
		return fmt.Errorf("missing SandboxExtractor implementation")
	}
	if monitorconfig.Workers < 1 {
		return fmt.Errorf("number of Kubernetes monitor workers must be at least 1")
	}

	// Setting up Kubernetes
	m.kubeCfg = kubeCfg
	m.localNode = monitorconfig.Nodename
	m.enableHostPods = monitorconfig.EnableHostPods
	m.metadataExtractor = monitorconfig.MetadataExtractor
	m.netclsProgrammer = monitorconfig.NetclsProgrammer
	m.sandboxExtractor = monitorconfig.SandboxExtractor
	m.resetNetcls = monitorconfig.ResetNetcls
	m.workers = monitorconfig.Workers
	m.criRuntimeService = monitorconfig.CRIRuntimeService

	return nil
}

// Run starts the monitor.
func (m *PodMonitor) Run(ctx context.Context) error {
	log.SetLogger(zapr.NewLogger(zap.L()))
	if m.kubeCfg == nil {
		return errors.New("pod: missing kubeconfig")
	}

	if err := m.handlers.IsComplete(); err != nil {
		return fmt.Errorf("pod: %s", err.Error())
	}

	nativeClient, err := kubernetes.NewForConfig(m.kubeCfg)
	if err != nil {
		return fmt.Errorf("pod: failed to create native kubernetes client: %s", err.Error())
	}

	// ensure to run the reset net_cls
	// NOTE: we also call this during resync, however, that is not called at startup
	if m.resetNetcls == nil {
		return errors.New("pod: missing net_cls reset implementation")
	}
	if err := m.resetNetcls(ctx); err != nil {
		return fmt.Errorf("pod: failed to reset net_cls cgroups: %s", err.Error())
	}

	syncPeriod := time.Hour * 6
	mgr, err := manager.New(m.kubeCfg, manager.Options{
		SyncPeriod: &syncPeriod,
	})
	if err != nil {
		return fmt.Errorf("pod: %s", err.Error())
	}

	// if we have CRI, we are going to start a PLEG for event generation
	var pleg cripleg.PodLifecycleEventGenerator
	var plegSetupComplete bool
	if m.criRuntimeService != nil {
		// get the runtime name first
		versResp, err := m.criRuntimeService.Version(criClientVersion)
		if err != nil {
			zap.L().Warn("failed to query CRI about the version, not going to start the CRI PLEG", zap.Error(err))
		}
		if err == nil {
			pleg = cripleg.NewCRIPLEG(m.criRuntimeService, versResp.GetRuntimeName())
			if err := mgr.Add(manager.RunnableFunc(func(s <-chan struct{}) error {
				pleg.Start(s)
				<-s
				return nil
			})); err != nil {
				zap.L().Error("failed to add the CRI PLEG to the manager")
			}
			if err == nil {
				if err := mgr.Add(manager.RunnableFunc(func(s <-chan struct{}) error {
				loop:
					for {
						select {
						case <-s:
							break loop
						case ev := <-pleg.Watch():
							if ev != nil {
								zap.L().Debug("received PLEG event", zap.String("ID", string(ev.ID)), zap.String("NamespacedName", ev.NamespacedName.String()), zap.String("Type", string(ev.Type)), zap.Any("data", ev.Data))
								if ev.NamespacedName.Name == "" || ev.NamespacedName.Namespace == "" {
									zap.L().Debug("received invalid PLEG event", zap.String("ID", string(ev.ID)), zap.String("NamespacedName", ev.NamespacedName.String()), zap.String("Type", string(ev.Type)), zap.Any("data", ev.Data))
									break
								}
								m.eventsCh <- event.GenericEvent{
									Meta: &metav1.ObjectMeta{
										UID:       ev.ID,
										Name:      ev.NamespacedName.Name,
										Namespace: ev.NamespacedName.Namespace,
									},
								}
							}
						}
					}
					return nil
				})); err != nil {
					zap.L().Error("failed to add the PLEG watcher to the manager")
				}
				plegSetupComplete = true
			}
		}
	}

	nativeInformers := informers.NewSharedInformerFactory(nativeClient, syncPeriod)
	if err := mgr.Add(manager.RunnableFunc(func(s <-chan struct{}) error {
		nativeInformers.Start(s)
		<-s
		return nil
	})); err != nil {
		return fmt.Errorf("pod: failed to add native informers to manager: %s", err.Error())
	}

	// create the policy engine queue
	policyEngineQueue := queue.NewPolicyEngineQueue(m.handlers, 10000)
	if err := mgr.Add(policyEngineQueue); err != nil {
		return fmt.Errorf("pod: failed to add policy engine queue to manager: %s", err.Error())
	}

	// Create the delete event controller first
	// NOTE: we don't want to rely on a cache here, _always_ read from the API directly
	dcClient, err := client.New(m.kubeCfg, client.Options{
		Scheme: mgr.GetScheme(),
		Mapper: mgr.GetRESTMapper(),
	})
	if err != nil {
		return fmt.Errorf("failed to create uncached client for delete controller")
	}
	dc := NewDeleteController(dcClient, m.handlers, m.sandboxExtractor, m.eventsCh)
	if err := mgr.Add(dc); err != nil {
		return fmt.Errorf("pod: %s", err.Error())
	}

	// Create the main controller for the monitor
	r := newReconciler(mgr, m.handlers, m.metadataExtractor, m.netclsProgrammer, m.sandboxExtractor, m.localNode, m.enableHostPods, dc.GetDeleteCh(), dc.GetReconcileCh())
	if err := addController(mgr, r, m.workers, m.eventsCh, nativeInformers, plegSetupComplete); err != nil {
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
	if m.resetNetcls != nil {
		if err := m.resetNetcls(ctx); err != nil {
			return err
		}
	}

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
