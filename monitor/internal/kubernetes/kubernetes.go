package kubernetesmonitor

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
