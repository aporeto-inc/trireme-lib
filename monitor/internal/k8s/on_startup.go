package k8smonitor

import (
	"context"
	"fmt"
	"sync"

	"go.aporeto.io/enforcerd/internal/extractors/containermetadata"
	"go.uber.org/zap"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

func (m *K8sMonitor) onStartup(ctx context.Context, startEvent startEventFunc) error {
	// wait for runc-proxy to be started before continuing with syncing state
	if !m.isCniInstalledOrRuncProxyStarted() {
		zap.L().Info("K8sMonitor: waiting for CNI plugin to be installed and configured...")
		select {
		case <-ctx.Done():
			return fmt.Errorf("K8sMonitor: startup was canceled: %w", ctx.Err())
		case <-m.cniInstalledOrRuncProxyStartedCh:
			zap.L().Info("K8sMonitor: CNI plugin is ready. Continuing startup.")
		}
	}

	sandboxList, err := m.criRuntimeService.ListPodSandbox(&runtimeapi.PodSandboxFilter{
		State: &runtimeapi.PodSandboxStateValue{
			State: runtimeapi.PodSandboxState_SANDBOX_READY,
		},
	})
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	m.handlers.ResyncLock.RLock()
	defer m.handlers.ResyncLock.RUnlock()
	for _, sandbox := range sandboxList {
		// extract common Kubernetes metadata from the filesystem
		// technically CRI provides us with everything we need right now,
		// however, this way the results are consistent and easier to maintain in the future
		sandboxID := sandbox.GetId()
		kmd, err := extractKmdFromCRISandbox(sandboxID)
		if err != nil {
			zap.L().Error("K8sMonitor: onStartup: failed to extract sandbox metadata. Skipping initialization for this pod...", zap.String("sandboxID", sandboxID), zap.Error(err))
			continue
		}

		// fire away a start event
		wg.Add(1)
		go func(ctx context.Context, id string, m containermetadata.CommonKubernetesContainerMetadata) {
			if err := startEvent(ctx, m, 0); err != nil {
				zap.L().Error("K8sMonitor: onStartup: failed to send start event", zap.String("sandboxID", id), zap.Error(err))
			}
			wg.Done()
		}(ctx, sandboxID, kmd)
	}
	wg.Wait()

	return nil
}

var extractor = containermetadata.AutoDetect()

func extractKmdFromCRISandbox(sandboxID string) (containermetadata.CommonKubernetesContainerMetadata, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("sandbox ID empty")
	}
	containerArgs := containermetadata.NewRuncArguments(containermetadata.StartAction, sandboxID)
	if !extractor.Has(containerArgs) {
		return nil, fmt.Errorf("failed to detect sandbox on filesystem")
	}
	_, kmd, err := extractor.Extract(containerArgs)
	if err != nil {
		return nil, fmt.Errorf("failed to extract metadata of sandbox from filesystem: %s", err)
	}
	if kmd == nil {
		zap.L().Error("K8sMonitor: onStartup: failed to this container as Kubernetes sandbox from filesystem", zap.String("sandboxID", sandboxID), zap.Error(err))
		return nil, fmt.Errorf("failed to detect this container as Kubernetes sandbox from filesystem")
	}
	return kmd, nil
}
