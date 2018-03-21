package kubernetesmonitor

import (
	"fmt"

	"github.com/aporeto-inc/trireme-lib/policy"
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

func (m *KubernetesMonitor) consolidateKubernetesTags(runtime policy.RuntimeReader) (*policy.PURuntime, error) {

	podName, ok := runtime.Tag(KubernetesPodNameIdentifier)
	if !ok {
		return nil, fmt.Errorf("Error getting Kubernetes Pod name")
	}
	podNamespace, ok := runtime.Tag(KubernetesPodNamespaceIdentifier)
	if !ok {
		return nil, fmt.Errorf("Error getting Kubernetes Pod namespace")
	}

	pod, err := m.kubernetesClient.Pod(podName, podNamespace)
	if err != nil {
		return nil, fmt.Errorf("Couldn't get labels for pod %s : %v", podName, err)
	}

	// If IP is empty, wait for an UpdatePodEvent with the Actual PodIP. Not ready to be activated now.
	if pod.Status.PodIP == "" {
		return nil, nil
	}
	// If Pod is running in the hostNS, no activation (not supported).
	if pod.Status.PodIP == pod.Status.HostIP {
		return nil, nil
	}

	podLabels := pod.GetLabels()
	if podLabels == nil {
		return nil, nil
	}
	fmt.Printf("\n\n Tags before: %v \n\n", runtime.Tags())

	tags := policy.NewTagStoreFromMap(podLabels)
	tags.AppendKeyValue(UpstreamNameIdentifier, podName)
	tags.AppendKeyValue(UpstreamNamespaceIdentifier, podNamespace)

	originalRuntime, ok := runtime.(*policy.PURuntime)
	if !ok {
		return nil, fmt.Errorf("Error casting puruntime")
	}

	newRuntime := originalRuntime.Clone()
	newRuntime.SetTags(tags)

	fmt.Printf("\n\n Tags after: %v \n\n", newRuntime.Tags())

	return newRuntime, nil
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
