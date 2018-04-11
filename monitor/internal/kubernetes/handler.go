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
	zap.L().Debug("dockermonitor event", zap.String("puID", puID), zap.String("eventType", string(event)))

	// We check first if this is a Kubernetes managed container
	podNamespace, podName, err := getKubernetesInformation(runtime)
	if err != nil {
		return err
	}

	// We get the information for that specific POD from Kubernetes API
	pod, err := m.getPod(podNamespace, podName)
	if err != nil {
		return err
	}

	// The KubernetesMetadataExtractor combines the information coming from Docker (runtime)
	// and from Kube (pod) in order to create a KubernetesRuntime.
	// The managedContainer parameters define if this container should be ignored.
	kubernetesRuntime, managedContainer, err := m.kubernetesExtractor(runtime, pod)
	if err != nil {
		return fmt.Errorf("error while processing Kubernetes pod %s/%s for container %s %s", podNamespace, podName, puID, err)
	}

	// UnmanagedContainers are simply ignored. No policy is associated.
	if !managedContainer {
		zap.L().Debug("unmanaged Kubernetes container", zap.String("puID", puID), zap.String("podNamespace", podNamespace), zap.String("podName", podName))
		return nil
	}

	// We keep the cache uptoDate for future queries
	m.cache.updatePUIDCache(podNamespace, podName, puID, runtime)

	// The event is then sent to the upstream policyResolver
	return m.handlers.Policy.HandlePUEvent(ctx, puID, event, kubernetesRuntime)
}

// getKubernetesInformation returns the name and namespace from a standard Docker runtime, if the docker container is associated at all with Kubernetes
func getKubernetesInformation(runtime policy.RuntimeReader) (string, string, error) {
	podNamespace, ok := runtime.Tag(KubernetesPodNamespaceIdentifier)
	if !ok {
		return "", "", fmt.Errorf("Error getting Kubernetes Pod namespace")
	}
	podName, ok := runtime.Tag(KubernetesPodNameIdentifier)
	if !ok {
		return "", "", fmt.Errorf("Error getting Kubernetes Pod name")
	}

	return podNamespace, podName, nil
}
