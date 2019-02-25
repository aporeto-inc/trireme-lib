package extractors

import (
	"fmt"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/policy"

	corev1 "k8s.io/api/core/v1"
)

// KubernetesPodNameIdentifier is the label used by Docker for the K8S pod name.
const KubernetesPodNameIdentifier = "@usr:io.kubernetes.pod.name"

// KubernetesPodNamespaceIdentifier is the label used by Docker for the K8S namespace.
const KubernetesPodNamespaceIdentifier = "@usr:io.kubernetes.pod.namespace"

// KubernetesContainerNameIdentifier is the label used by Docker for the K8S container name.
const KubernetesContainerNameIdentifier = "@usr:io.kubernetes.container.name"

// KubernetesInfraContainerName is the name of the infra POD.
const KubernetesInfraContainerName = "POD"

// UpstreamOldNameIdentifier is the identifier used to identify the nane on the resulting PU
// TODO: Remove OLDTAGS
const UpstreamOldNameIdentifier = "@k8s:name"

// UpstreamNameIdentifier is the identifier used to identify the nane on the resulting PU
const UpstreamNameIdentifier = "@app:k8s:name"

// UpstreamOldNamespaceIdentifier is the identifier used to identify the nanespace on the resulting PU
const UpstreamOldNamespaceIdentifier = "@k8s:namespace"

// UpstreamNamespaceIdentifier is the identifier used to identify the nanespace on the resulting PU
const UpstreamNamespaceIdentifier = "@app:k8s:namespace"

// UserLabelPrefix is the label prefix for all user defined labels
const UserLabelPrefix = "@usr:"

// KubernetesMetadataExtractorType is an extractor function for Kubernetes.
// It takes as parameter a Pod Kubernetes definition and returns a PolicyRuntime
type KubernetesMetadataExtractorType func(pod *corev1.Pod) (*policy.PURuntime, error)

// DefaultKubernetesMetadataExtractor is a default implementation for the medatadata extractor for Kubernetes
func DefaultKubernetesMetadataExtractor(pod *corev1.Pod) (*policy.PURuntime, error) {
	var ret *policy.PURuntime

	if pod == nil {
		return nil, fmt.Errorf("empty pod")
	}

	podLabels := pod.GetLabels()
	if podLabels == nil {
		podLabels = make(map[string]string)
	}

	tags := policy.NewTagStoreFromMap(podLabels)
	tags.AppendKeyValue(UpstreamNameIdentifier, pod.GetName())
	tags.AppendKeyValue(UpstreamNamespaceIdentifier, pod.GetNamespace())
	tags.AppendKeyValue("@app:k8s:serviceAccountName", pod.Spec.ServiceAccountName)
	tags.AppendKeyValue("@app:k8s:UID", string(pod.UID))

	podAnnotations := pod.GetAnnotations()
	if podAnnotations != nil {
		for k, _v := range podAnnotations {
			v := _v
			if len(_v) == 0 {
				v = "<empty>"
			}
			tags.AppendKeyValue(k, v)
		}
	}

	ipa := policy.ExtendedMap{
		"bridge": pod.Status.PodIP,
	}

	// TODO: extract cgroup information

	if pod.Spec.HostNetwork {
		ret = policy.NewPURuntime(pod.Name, 0, "", tags, ipa, common.LinuxProcessPU, nil)
	} else {
		ret = policy.NewPURuntime(pod.Name, 0, "", tags, ipa, common.KubernetesPU, nil)
	}
	return ret, nil
}
