package kubernetesmonitor

import (
	"context"
	"fmt"

	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/policy"
	"go.uber.org/zap"
	api "k8s.io/api/core/v1"
)

// General logic for handling logic fron the DockerMonitor ss the following:
// The only interesting event is the Start and Die event. All the other events are ignored

// Those events are then put together with the Pod events received from the Kubernetes API.
// Once both are received and are consistent, the Pod get activated.

// HandlePUEvent is called by all monitors when a PU event is generated. The implementer
// is responsible to update all components by explicitly adding a new PU.
// Specifically for Kubernetes, The monitor handles the downstream events from Docker.
func (m *KubernetesMonitor) HandlePUEvent(ctx context.Context, puID string, event common.Event, dockerRuntime policy.RuntimeReader) error {
	zap.L().Debug("dockermonitor event", zap.String("puID", puID), zap.String("eventType", string(event)))

	var kubernetesRuntime policy.RuntimeReader

	// If the event coming from DockerMonitor is start or create, we will get a meaningful PURuntime from
	// DockerMonitor. We can use it and combine it with the pod information on Kubernetes API.
	if event == common.EventStart || event == common.EventCreate {
		// We check first if this is a Kubernetes managed container
		podNamespace, podName, err := getKubernetesInformation(dockerRuntime)
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
		kubernetesRuntime, managedContainer, err := m.kubernetesExtractor(dockerRuntime, pod)
		if err != nil {
			return fmt.Errorf("error while processing Kubernetes pod %s/%s for container %s %s", podNamespace, podName, puID, err)
		}

		// UnmanagedContainers are simply ignored. No policy is associated.
		if !managedContainer {
			zap.L().Debug("unmanaged Kubernetes container on create or start", zap.String("puID", puID), zap.String("podNamespace", podNamespace), zap.String("podName", podName))
			return nil
		}

		// We keep the cache uptoDate for future queries
		m.cache.updatePUIDCache(podNamespace, podName, puID, dockerRuntime, kubernetesRuntime)
	} else {

		// We check if this PUID was previously managed. We only sent the event upstream to the resolver if it was managed on create or start.
		kubernetesRuntime := m.cache.getKubernetesRuntimeByPUID(puID)
		if kubernetesRuntime == nil {
			zap.L().Debug("unmanaged Kubernetes container", zap.String("puID", puID))
			return nil
		}
	}

	if event == common.EventDestroy {
		// Time to kill the cache entry
		m.cache.deletePUIDEntry(puID)
	}

	// The event is then sent to the upstream policyResolver
	return m.handlers.Policy.HandlePUEvent(ctx, puID, event, kubernetesRuntime)
}

// RefreshPUs is used to resend an update event to the Upstream Policy Resolver in case of an update is needed.
func (m *KubernetesMonitor) RefreshPUs(ctx context.Context, pod *api.Pod) error {
	if pod == nil {
		return fmt.Errorf("pod is nil")
	}

	puIDs := m.cache.getPUIDsbyPod(pod.GetNamespace(), pod.GetNamespace())

	for _, puid := range puIDs {
		dockerRuntime := m.cache.getDockerRuntimeByPUID(puid)
		if dockerRuntime == nil {
			continue
		}

		kubernetesRuntime, managedContainer, err := m.kubernetesExtractor(runtime, pod)
		if err != nil {
			return fmt.Errorf("error while processing Kubernetes pod %s/%s for container %s %s", pod.GetNamespace(), pod.GetName(), puid, err)
		}

		// UnmanagedContainers are simply ignored. It should not come this far if it is a non managed container anyways.
		if !managedContainer {
			zap.L().Debug("unmanaged Kubernetes container", zap.String("puID", puid), zap.String("podNamespace", pod.GetNamespace()), zap.String("podName", pod.GetName()))
			continue
		}

		// We keep the cache uptoDate for future queries
		m.cache.updatePUIDCache(podNamespace, podName, puid, dockerRuntime, kubernetesRuntime)

		if err := m.handlers.Policy.HandlePUEvent(ctx, puid, common.EventUpdate, kubernetesRuntime); err != nil {
			return err
		}
	}

	return nil
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
