package kubernetesmonitor

import (
	"context"
	"fmt"

	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/policy"
	"go.uber.org/zap"
)

// General logic for handling logic fron the DockerMonitor ss the following:
// The only interesting event is the Start and Die event. All the other events are ignored

// Those events are then put together with the Pod events received from the Kubernetes API.
// Once both are received and are consistent, the Pod get activated.

// HandlePUEvent is called by all monitors when a PU event is generated. The implementer
// is responsible to update all components by explicitly adding a new PU.
// Specifically for Kubernetes, The monitor handles the downstream events from Docker.
func (m *KubernetesMonitor) HandlePUEvent(ctx context.Context, puID string, event common.Event, runtime policy.RuntimeReader) error {
	zap.L().Debug("dockermonitor event", zap.String("puID", puID))

	// Other events are irrelevant for the Kubernetes workflow
	if event != common.EventStart && event != common.EventStop {
		return nil
	}

	process, err := isPodInfraContainer(runtime)
	if err != nil {
		return fmt.Errorf("Error while processing Kubernetes pod %s", err)
	}

	if !process {
		return nil
	}

	kubernetesRuntime, err := m.consolidateKubernetesTags(runtime)
	if err != nil {
		return fmt.Errorf("Error while processing Kubernetes pod %s", err)
	}

	podName, ok := runtime.Tag(KubernetesPodNameIdentifier)
	if !ok {
		return fmt.Errorf("Error getting Kubernetes Pod name")
	}
	podNamespace, ok := runtime.Tag(KubernetesPodNamespaceIdentifier)
	if !ok {
		return fmt.Errorf("Error getting Kubernetes Pod namespace")
	}

	podEntry := m.cache.getOrCreatePodFromCache(podNamespace, podName)
	podEntry.Lock()
	defer podEntry.Unlock()

	podEntry.runtime = kubernetesRuntime
	if podEntry.pod != nil {
		// Both runtime and Pods are here, activate
	}

	return m.handlers.Policy.HandlePUEvent(ctx, puID, event, kubernetesRuntime)
}
