package constants

const (
	// DefaultDockerSocket is the default socket to use to communicate with docker
	DefaultDockerSocket = "/var/run/docker.sock"

	// DefaultDockerSocketType is unix
	DefaultDockerSocketType = "unix"
)

const (
	// DockerHostMode is the string of the network mode that indicates a host namespace
	DockerHostMode = "host"
	// DockerLinkedMode is the string of the network mode that indicates shared network namespace
	DockerLinkedMode = "container:"
)

// DockerMonitorMode defines the different modes the docker monitor can be in depending on the environment where trireme-lib is running
type DockerMonitorMode int

const (
	// DockerMode is a mode for docker monitor when trireme is running on host with just a docker daemon
	DockerMode DockerMonitorMode = iota

	// KubernetesMode is a mode for docker monitor when trireme is running on host which is part of a kubernetes cluster
	KubernetesMode

	// NoProxyMode is a mode for docker monitor when trireme is running on host which is part of ECS/AWS cluster
	NoProxyMode
)
