package constants

const (
	// DefaultDockerSocket is the default socket to use to communicate with docker
	DefaultDockerSocket = "/var/run/docker.sock"

	// DefaultDockerSocketType is unix
	DefaultDockerSocketType = "unix"

	// K8sPodName is pod name of K8s pod.
	K8sPodName = "io.kubernetes.pod.name"

	// K8sPodNamespace is the namespace of K8s pod.
	K8sPodNamespace = "io.kubernetes.pod.namespace"
)

const (
	// DockerHostMode is the string of the network mode that indicates a host namespace
	DockerHostMode = "host"
	// DockerLinkedMode is the string of the network mode that indicates shared network namespace
	DockerLinkedMode = "container:"

	// DockerHostPUID represents the PUID of the host network container.
	DockerHostPUID = "HostPUID"
)
