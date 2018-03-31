package kubernetesmonitor

import (
	"context"
	"fmt"
	"time"

	"github.com/aporeto-inc/trireme-lib/common"

	"github.com/aporeto-inc/trireme-lib/policy"
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

// consolidateKubernetesTags uses the Dockewr runtime and pod information in order to build a Kubernetes specific runtime
func (m *KubernetesMonitor) consolidateKubernetesTags(runtime policy.RuntimeReader, pod *api.Pod) (*policy.PURuntime, error) {
	var err error

	if runtime == nil {
		return nil, fmt.Errorf("empty runtime")
	}

	if pod == nil {
		zap.L().Debug("no pod cached, querying Kubernetes API")

		podName, ok := runtime.Tag(KubernetesPodNameIdentifier)
		if !ok {
			return nil, fmt.Errorf("Error getting Kubernetes Pod name")
		}
		podNamespace, ok := runtime.Tag(KubernetesPodNamespaceIdentifier)
		if !ok {
			return nil, fmt.Errorf("Error getting Kubernetes Pod namespace")
		}

		pod, err = m.kubernetesClient.Pod(podName, podNamespace)
		if err != nil {
			return nil, fmt.Errorf("Couldn't get labels for pod %s : %v", podName, err)
		}
	}

	// If Pod is running in the hostNS, no activation (not supported).
	// if pod.Status.PodIP == pod.Status.HostIP {
	// 	zap.L().Debug("pod running in host mode.")
	// 	if !m.EnableHostPods {
	// 		return nil, nil
	// 	}
	// }

	podLabels := pod.GetLabels()
	if podLabels == nil {
		zap.L().Debug("couldn't get labels.")
		return nil, nil
	}

	tags := policy.NewTagStoreFromMap(podLabels)
	tags.AppendKeyValue(UpstreamNameIdentifier, pod.GetName())
	tags.AppendKeyValue(UpstreamNamespaceIdentifier, pod.GetNamespace())

	originalRuntime, ok := runtime.(*policy.PURuntime)
	if !ok {
		return nil, fmt.Errorf("Error casting puruntime")
	}

	newRuntime := originalRuntime.Clone()
	newRuntime.SetTags(tags)

	zap.L().Debug("kubernetes runtime tags", zap.String("name", pod.GetName()), zap.String("namespace", pod.GetNamespace()), zap.Strings("tags", newRuntime.Tags().GetSlice()))

	return newRuntime, nil
}

func (m *KubernetesMonitor) addPod(addedPod *api.Pod) error {
	zap.L().Debug("pod added event", zap.String("name", addedPod.GetName()), zap.String("namespace", addedPod.GetNamespace()))

	// This event is not needed as the trigger is the  DockerMonitor event
	// The pod obejct is cached in order to reuse it and avoid an API request possibly laster on

	_, err := m.cache.updatePodEntry(addedPod.GetNamespace(), addedPod.GetName(), addedPod)
	if err != nil {
		return fmt.Errorf("error updating cache entry %s", err)
	}

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
	podEntry, err := m.cache.updatePodEntry(updatedPod.GetNamespace(), updatedPod.GetName(), updatedPod)
	if err != nil {
		return fmt.Errorf("error updating cache entry %s", err)
	}

	return m.sendPodEvent(context.TODO(), podEntry, common.EventUpdate)
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

// isPodInfraContainer returns true if the runtime represents the infra container for the POD
func isPodInfraContainer(runtime policy.RuntimeReader) (bool, error) {
	// The Infra container can be found by checking env. variable.
	tagContent, ok := runtime.Tag(KubernetesContainerNameIdentifier)
	if !ok || tagContent != KubernetesInfraContainerName {
		return false, nil
	}

	return true, nil
}

// hasSynced sends an event on the Sync chan when the attachedController finished syncing.
func hasSynced(sync chan struct{}, controller kubecache.Controller) {
	for true {
		if controller.HasSynced() {
			sync <- struct{}{}
			return
		}
		<-time.After(100 * time.Millisecond)
	}
}
