package k8sruncmonitor

import (
	"context"
	"errors"
	"fmt"

	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/monitor/registerer"
	"go.aporeto.io/trireme-lib/utils/cri"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// K8sRuncMonitor is the runc proxy monitor for Kubernetes.
type K8sRuncMonitor struct {
	nodename          string
	handlers          *config.ProcessorConfig
	metadataExtractor extractors.PodMetadataExtractor
	netclsProgrammer  extractors.PodNetclsProgrammer
	resetNetcls       extractors.ResetNetclsKubepods
	kubeCfg           *rest.Config
	criRuntimeService cri.ExtendedRuntimeService
	server            *RuncProxyServer
}

// New returns a new kubernetes monitor.
func New() *K8sRuncMonitor {
	return &K8sRuncMonitor{}
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (m *K8sRuncMonitor) SetupConfig(registerer registerer.Registerer, cfg interface{}) error {

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
	if kubernetesconfig.CRIRuntimeService == nil {
		return fmt.Errorf("missing CRIRuntimeService implementation")
	}
	// Setting up Kubernetes
	m.kubeCfg = kubeCfg
	m.nodename = kubernetesconfig.Nodename
	m.metadataExtractor = kubernetesconfig.MetadataExtractor
	m.netclsProgrammer = kubernetesconfig.NetclsProgrammer
	m.resetNetcls = kubernetesconfig.ResetNetcls
	m.criRuntimeService = kubernetesconfig.CRIRuntimeService

	return nil
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (m *K8sRuncMonitor) SetupHandlers(c *config.ProcessorConfig) {
	m.handlers = c
}

// Run starts the monitor implementation.
func (m *K8sRuncMonitor) Run(ctx context.Context) error {
	if m.kubeCfg == nil {
		return errors.New("k8srunc: missing kubeconfig")
	}

	if err := m.handlers.IsComplete(); err != nil {
		return fmt.Errorf("k8srunc: handlers are not complete: %s", err.Error())
	}
	c, err := kubernetes.NewForConfig(m.kubeCfg)
	if err != nil {
		return err
	}

	// ensure to run the reset net_cls
	// NOTE: we also call this during resync, however, that is not called at startup (we call ResyncWithAllPods instead before we return)
	if m.resetNetcls == nil {
		return errors.New("k8srunc: missing net_cls reset implementation")
	}
	if err := m.resetNetcls(ctx); err != nil {
		return fmt.Errorf("k8srunc: failed to reset net_cls cgroups: %s", err.Error())
	}

	m.server = NewRuncProxyServer(m.handlers, m.criRuntimeService, c, m.metadataExtractor)
	go m.server.ListenAndServe()

	return nil
}

// Resync should resynchronize PUs. This should be done while starting up.
func (m *K8sRuncMonitor) Resync(ctx context.Context) error {
	return nil
}
