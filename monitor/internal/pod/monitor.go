// +build linux !windows

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

	"go.uber.org/zap"
)

// PodMonitor implements a monitor that sends pod events upstream
// It is implemented as a filter on the standard DockerMonitor.
// It gets all the PU events from the DockerMonitor and if the container is the POD container from Kubernetes,
// It connects to the Kubernetes API and adds the tags that are coming from Kuberntes that cannot be found
type PodMonitor struct {
	localNode                 string
	handlers                  *config.ProcessorConfig
	metadataExtractor         extractors.PodMetadataExtractor
	netclsProgrammer          extractors.PodNetclsProgrammer
	pidsSetMaxProcsProgrammer extractors.PodPidsSetMaxProcsProgrammer
	resetNetcls               extractors.ResetNetclsKubepods
	sandboxExtractor          extractors.PodSandboxExtractor
	enableHostPods            bool
	workers                   int
	kubeCfg                   *rest.Config
	kubeClient                client.Client
	eventsCh                  chan event.GenericEvent
	resyncInfo                *ResyncInfoChan
}

// New returns a new kubernetes monitor.
func New() *PodMonitor {
	podMonitor := &PodMonitor{
		eventsCh:   make(chan event.GenericEvent),
		resyncInfo: NewResyncInfoChan(),
	}

	return podMonitor
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (m *PodMonitor) SetupConfig(_ registerer.Registerer, cfg interface{}) error {

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

	if kubernetesconfig.ResetNetcls == nil {
		return fmt.Errorf("missing reset net_cls implementation")
	}
	if kubernetesconfig.SandboxExtractor == nil {
		return fmt.Errorf("missing SandboxExtractor implementation")
	}
	if kubernetesconfig.Workers < 1 {
		return fmt.Errorf("number of Kubernetes monitor workers must be at least 1")
	}
	// Setting up Kubernetes
	m.kubeCfg = kubeCfg
	m.localNode = kubernetesconfig.Nodename
	m.enableHostPods = kubernetesconfig.EnableHostPods
	m.metadataExtractor = kubernetesconfig.MetadataExtractor
	m.netclsProgrammer = kubernetesconfig.NetclsProgrammer
	m.pidsSetMaxProcsProgrammer = kubernetesconfig.PidsSetMaxProcsProgrammer
	m.sandboxExtractor = kubernetesconfig.SandboxExtractor
	m.resetNetcls = kubernetesconfig.ResetNetcls
	m.workers = kubernetesconfig.Workers

	return nil
}

// Run starts the monitor.
func (m *PodMonitor) Run(ctx context.Context) error {
	if m.kubeCfg == nil {
		return errors.New("pod: missing kubeconfig")
	}

	if err := m.handlers.IsComplete(); err != nil {
		return fmt.Errorf("pod: handlers are not complete: %s", err.Error())
	}

	// ensure to run the reset net_cls
	// NOTE: we also call this during resync, however, that is not called at startup (we call ResyncWithAllPods instead before we return)
	if m.resetNetcls == nil {
		return errors.New("pod: missing net_cls reset implementation")
	}
	if err := m.resetNetcls(ctx); err != nil {
		return fmt.Errorf("pod: failed to reset net_cls cgroups: %s", err.Error())
	}

	// starts the manager in the background and will return once it is running
	// NOTE: This will block until the Kubernetes manager and all controllers are up. All errors are being handled within the function
	m.startManager(ctx)

	// call ResyncWithAllPods before we return from here
	// this will block until every pod at this point in time has been seeing at least one `Reconcile` call
	// we do this so that we build up our internal PU cache in the policy engine,
	// so that when we remove stale pods on startup, we don't remove them and create them again
	if err := ResyncWithAllPods(ctx, m.kubeClient, m.resyncInfo, m.eventsCh, m.localNode); err != nil {
		zap.L().Warn("Pod resync failed", zap.Error(err))
	}
	return nil
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

	return ResyncWithAllPods(ctx, m.kubeClient, m.resyncInfo, m.eventsCh, m.localNode)
}

const (
	startupWarningMessage = "pod: the Kubernetes controller did not start within the last 5s. Waiting..."
)

var (
	retrySleep          = time.Second * 3
	warningMessageSleep = time.Second * 5
	warningTimeout      = time.Second * 5
	managerNew          = manager.New
)

func (m *PodMonitor) startManager(ctx context.Context) {
	var mgr manager.Manager

	startTimestamp := time.Now()
	z := make(chan struct{})
	controllerStarted := make(chan struct{})

	go func() {
		// manager.New already contacts the Kubernetes API
		for {
			var err error
			mgr, err = managerNew(m.kubeCfg, manager.Options{})
			if err != nil {
				zap.L().Error("pod: new manager instantiation failed. Retrying in 3s...", zap.Error(err))
				time.Sleep(retrySleep)
				continue
			}
			break
		}

		// Create the delete event controller first
		dc := NewDeleteController(mgr.GetClient(), m.localNode, m.handlers, m.sandboxExtractor, m.eventsCh)
		for {
			if err := mgr.Add(dc); err != nil {
				zap.L().Error("pod: adding delete controller failed. Retrying in 3s...", zap.Error(err))
				time.Sleep(retrySleep)
				continue
			}
			break
		}

		// Create the main controller for the monitor
		for {
			if err := addController(
				mgr,
				newReconciler(mgr, m.handlers, m.metadataExtractor, m.netclsProgrammer, m.sandboxExtractor, m.localNode, m.enableHostPods, dc.GetDeleteCh(), dc.GetReconcileCh(), m.resyncInfo),
				m.workers,
				m.eventsCh,
			); err != nil {
				zap.L().Error("pod: adding main monitor controller failed. Retrying in 3s...", zap.Error(err))
				time.Sleep(retrySleep)
				continue
			}
			break
		}

		for {
			if err := mgr.Add(&runnable{ch: controllerStarted}); err != nil {
				zap.L().Error("pod: adding side controller failed. Retrying in 3s...", zap.Error(err))
				time.Sleep(retrySleep)
				continue
			}
			break
		}

		// starting the manager is a bit awkward:
		// - it does not use contexts
		// - we pass in a fake signal handler channel
		// - we start another go routine which waits for the context to be cancelled
		//   and closes that channel if that is the case

		for {
			if err := mgr.Start(z); err != nil {
				zap.L().Error("pod: manager start failed. Retrying in 3s...", zap.Error(err))
				time.Sleep(retrySleep)
				continue
			}
			break
		}
	}()

waitLoop:
	for {
		select {
		case <-ctx.Done():
			close(z)
		case <-time.After(warningMessageSleep):
			// we give everything 5 seconds to report back before we issue a warning
			zap.L().Warn(startupWarningMessage)
		case <-controllerStarted:
			m.kubeClient = mgr.GetClient()
			t := time.Since(startTimestamp)
			if t > warningTimeout {
				zap.L().Warn("pod: controller startup finished, but took longer than expected", zap.Duration("duration", t))
			} else {
				zap.L().Debug("pod: controller startup finished", zap.Duration("duration", t))
			}
			break waitLoop
		}
	}
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
