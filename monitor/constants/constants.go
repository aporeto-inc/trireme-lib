package constants

const (
	// DefaultDockerSocket is the default socket to use to communicate with docker
	DefaultDockerSocket = "/var/run/docker.sock"

	// DefaultDockerSocketType is unix
	DefaultDockerSocketType = "unix"

	// KubernetesPodNamespaceIdentifier is the label used by Docker for the K8S namespace.
	KubernetesPodNamespaceIdentifier = "@usr:io.kubernetes.pod.namespace"
)

const (
	// DockerHostMode is the string of the network mode that indicates a host namespace
	DockerHostMode = "host"
	// DockerLinkedMode is the string of the network mode that indicates shared network namespace
	DockerLinkedMode = "container:"
)
