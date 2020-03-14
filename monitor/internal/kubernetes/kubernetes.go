// +build !windows

package kubernetesmonitor

import (
	"context"
	"time"

	"go.uber.org/zap"
	api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	kubecache "k8s.io/client-go/tools/cache"
)

// KubernetesPodNameIdentifier is the label used by Docker for the K8S pod name.
const KubernetesPodNameIdentifier = "@usr:io.kubernetes.pod.name"

// KubernetesPodNamespaceIdentifier is the label used by Docker for the K8S namespace.
const KubernetesPodNamespaceIdentifier = "@usr:io.kubernetes.pod.namespace"

// KubernetesContainerNameIdentifier is the label used by Docker for the K8S container name.
const KubernetesContainerNameIdentifier = "@usr:io.kubernetes.container.name"

// KubernetesInfraContainerName is the name of the infra POD.
const KubernetesInfraContainerName = "POD"

// UpstreamNameIdentifier is the identifier used to identify the nane on the resulting PU
const UpstreamNameIdentifier = "k8s:name"

// UpstreamNamespaceIdentifier is the identifier used to identify the nanespace on the resulting PU
const UpstreamNamespaceIdentifier = "k8s:namespace"

func (m *KubernetesMonitor) addPod(addedPod *api.Pod) error {
	zap.L().Debug("pod added event", zap.String("name", addedPod.GetName()), zap.String("namespace", addedPod.GetNamespace()))

	// This event is not needed as the trigger is the  DockerMonitor event
	// The pod obejct is cached in order to reuse it and avoid an API request possibly laster on

	return nil
}

func (m *KubernetesMonitor) deletePod(deletedPod *api.Pod) error {
	zap.L().Debug("pod deleted event", zap.String("name", deletedPod.GetName()), zap.String("namespace", deletedPod.GetNamespace()))

	return nil
}

func (m *KubernetesMonitor) updatePod(oldPod, updatedPod *api.Pod) error {
	zap.L().Debug("pod modified event", zap.String("name", updatedPod.GetName()), zap.String("namespace", updatedPod.GetNamespace()))

	if !isPolicyUpdateNeeded(oldPod, updatedPod) {
		zap.L().Debug("no modified labels for Pod", zap.String("name", updatedPod.GetName()), zap.String("namespace", updatedPod.GetNamespace()))
		return nil
	}

	// This event requires sending the Runtime upstream again.
	// TODO: Use propagated context
	return m.RefreshPUs(context.TODO(), updatedPod)
}

func (m *KubernetesMonitor) getPod(podNamespace, podName string) (*api.Pod, error) {
	zap.L().Debug("no pod cached, querying Kubernetes API")

	// TODO: Use cached Kube Store (from a shared informer)
	return m.Pod(podName, podNamespace)
}

func isPolicyUpdateNeeded(oldPod, newPod *api.Pod) bool {
	if !(oldPod.Status.PodIP == newPod.Status.PodIP) {
		return true
	}
	if !labels.Equals(oldPod.GetLabels(), newPod.GetLabels()) {
		return true
	}
	return false
}

// hasSynced sends an event on the Sync chan when the attachedController finished syncing.
func hasSynced(sync chan struct{}, controller kubecache.Controller) {
	for {
		if controller.HasSynced() {
			sync <- struct{}{}
			return
		}
		<-time.After(100 * time.Millisecond)
	}
}
