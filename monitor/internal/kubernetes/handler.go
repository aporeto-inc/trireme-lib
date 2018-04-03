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

	switch event {
	case common.EventStart:

		podName, ok := runtime.Tag(KubernetesPodNameIdentifier)
		if !ok {
			return fmt.Errorf("Error getting Kubernetes Pod name")
		}
		podNamespace, ok := runtime.Tag(KubernetesPodNamespaceIdentifier)
		if !ok {
			return fmt.Errorf("Error getting Kubernetes Pod namespace")
		}

		podEntry := m.cache.createPodEntry(podNamespace, podName, puID, runtime)
		podEntry.Lock()
		defer podEntry.Unlock()

		return m.sendPodEvent(ctx, podEntry, event)

	case common.EventDestroy:
		podEntry, err := m.cache.getPodByPUID(puID)
		if err != nil {
			// If the pod is not found in the cache, we issue a warning.
			zap.L().Warn("error managing delete event. Not found in cache", zap.String("puID", puID), zap.String("eventType", string(event)), zap.Error(err))
			return nil
		}

		podEntry.Lock()
		defer podEntry.Unlock()

		return m.sendPodEvent(ctx, podEntry, event)

	default:
		// Other events are irrelevant for the Kubernetes workflow
		return nil
	}
}

// sendPodEvent sends the eveng to the policy resolver based on the podEntry cached.
func (m *KubernetesMonitor) sendPodEvent(ctx context.Context, podEntry *podCacheEntry, event common.Event) error {
	if podEntry.puID == "" {
		return fmt.Errorf("puID not set yet, container not seen from docker yet")
	}

	if podEntry.runtime == nil {
		return fmt.Errorf("runtime not set for podEntry")
	}

	// In case the pod is not there yet, we query Kubernetes API manually.
	if podEntry.pod == nil {
		zap.L().Debug("no pod cached, querying Kubernetes API")

		podName, ok := podEntry.runtime.Tag(KubernetesPodNameIdentifier)
		if !ok {
			return fmt.Errorf("Error getting Kubernetes Pod name")
		}
		podNamespace, ok := podEntry.runtime.Tag(KubernetesPodNamespaceIdentifier)
		if !ok {
			return fmt.Errorf("Error getting Kubernetes Pod namespace")
		}

		pod, err := m.kubernetesClient.Pod(podName, podNamespace)
		if err != nil {
			return fmt.Errorf("Couldn't get labels for pod %s : %s", podName, err)
		}

		podEntry.pod = pod
	}

	// TODO: Also keep the KubernetesRuntime in cache ? Probably not needed to calculate the consolidatedTags every single time.
	kubernetesRuntime, managedContainer, err := m.metadataExtractor(podEntry.runtime, podEntry.pod)
	if err != nil {
		return fmt.Errorf("error while processing Kubernetes pod for container %s %s", podEntry.puID, err)
	}

	// We only manage containers marked so from the metadata extractor
	if !managedContainer {
		return nil
	}

	return m.handlers.Policy.HandlePUEvent(ctx, podEntry.puID, event, kubernetesRuntime)
}
