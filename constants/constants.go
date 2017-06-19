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
	// ContainerPU indicates that this PU is a conctainer
	ContainerPU PUType = iota
	// LinuxProcessPU indicates that this is Linux process
	LinuxProcessPU
)

const (
	// DefaultRemoteArg is the default arguments for a remote enforcer
	DefaultRemoteArg = "enforce"
)
