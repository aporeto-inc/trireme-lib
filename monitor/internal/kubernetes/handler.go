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
	podName, podNamespace, err := getKubernetesInformation(runtime)
	if err != nil {
		return err
	}

	// We try to extract the Pod information from the cache
	podEntry := m.cache.createPodEntry(podNamespace, podName, puID, runtime)
	podEntry.Lock()
	defer podEntry.Unlock()

	if podEntry.pod == nil {
		zap.L().Debug("no pod cached, querying Kubernetes API")

		pod, err := m.kubernetesClient.Pod(podName, podNamespace)
		if err != nil {
			return fmt.Errorf("Couldn't get labels for pod %s : %s", podName, err)
		}

		podEntry.pod = pod
	}

	kubernetesRuntime, managedContainer, err := m.kubernetesExtractor(podEntry.runtime, podEntry.pod)
	if err != nil {
		return fmt.Errorf("error while processing Kubernetes pod for container %s %s", puID, err)
	}

	if !managedContainer {
		return nil
	}

	return m.handlers.Policy.HandlePUEvent(ctx, puID, event, kubernetesRuntime)

}

// getKubernetesInformation returns the name and namespace from a standard Docker runtime, if the docker container is associated at all with Kubernetes
func getKubernetesInformation(runtime policy.RuntimeReader) (string, string, error) {
	podName, ok := runtime.Tag(KubernetesPodNameIdentifier)
	if !ok {
		return "", "", fmt.Errorf("Error getting Kubernetes Pod name")
	}
	podNamespace, ok := runtime.Tag(KubernetesPodNamespaceIdentifier)
	if !ok {
		return "", "", fmt.Errorf("Error getting Kubernetes Pod namespace")
	}

	return podName, podNamespace, nil
}
