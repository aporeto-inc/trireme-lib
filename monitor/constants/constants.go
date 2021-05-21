package constants

const (
	// DefaultDockerSocket is the default socket to use to communicate with docker
	// it is canonicalized with utils.GetPathOnHostViaProcRoot() at point of use
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

	// UserLabelPrefix is the label prefix for all user defined labels
	UserLabelPrefix = "@usr:"
)

const (
	// K8sMonitorRegistrationName is used as the registration constant with the external sender (gRPC server)
	K8sMonitorRegistrationName = "k8sMonitor"

	// MonitorExtSenderName is the name of the monitor that registers with the trireme monitors to send events
	MonitorExtSenderName = "grpcMonitorServer"
)
