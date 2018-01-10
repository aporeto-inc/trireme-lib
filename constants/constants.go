package constants

const (
	// DefaultDockerSocket is the default socket to use to communicate with docker
	DefaultDockerSocket = "/var/run/docker.sock"

	// DefaultDockerSocketType is unix
	DefaultDockerSocketType = "unix"
)

// ModeType defines the mode of the enforcement and supervisor.
type ModeType int

const (
	// RemoteContainer indicates that the Supervisor is implemented in the
	// container namespace
	RemoteContainer ModeType = iota
	// LocalContainer indicates that the Supervisor is implemented in the host
	// namespace
	LocalContainer
	// LocalServer indicates that the Supervisor applies to Linux processes
	LocalServer
)

// ImplementationType defines the type of iptables or ipsets implementation
type ImplementationType int

const (
	// IPSets mandates an IPset supervisor implementation
	IPSets ImplementationType = iota
	// IPTables mandates an IPTable supervisor implementation
	IPTables
	// Remote indicates that this is a remote supervisor
)

// PUType defines the PU type
type PUType int

const (
	// ContainerPU indicates that this PU is a container
	ContainerPU PUType = iota
	// LinuxProcessPU indicates that this is Linux process
	LinuxProcessPU
	// KubernetesPU indicates that this is KubernetesPod
	KubernetesPU
	// UIDLoginPU -- PU representing a user session
	UIDLoginPU
	// TransientPU PU -- placeholder to run processing. This should not
	// be inserted in any cache. This is valid only for processing a packet
	TransientPU
)

const (
	// DefaultRemoteArg is the default arguments for a remote enforcer
	DefaultRemoteArg = "enforce"
	// DefaultConnMark is the default conn mark for all data packets
	DefaultConnMark = uint32(0xEEEE)
)

const (
	//DefaultProxyPort  the default port the l4 proxy listens on
	DefaultProxyPort = "5000"
	//DefaultProcMountPoint The default proc mountpoint
	DefaultProcMountPoint = "/proc"
	//DefaultAporetoProcMountPoint The aporeto proc mountpoint just in case we are launched with some specific docker config
	DefaultAporetoProcMountPoint = "/aporetoproc"
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
