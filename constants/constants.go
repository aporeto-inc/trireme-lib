package constants

const (
	// DefaultDockerSocket is the default socket to use to communicate with docker
	DefaultDockerSocket = "/var/run/docker.sock"

	// DefaultDockerSocketType is unix
	DefaultDockerSocketType = "unix"
)

// ModeType defines whether this is local or remote
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

// ImplementationType defines the type of implementation
type ImplementationType int

const (
	// IPSets mandates an IPset supervisor implementation
	IPSets ImplementationType = iota
	// IPTables mandates an IPTable supervisor implementation
	IPTables
	// Remote indicates that this is a remote supervisor
)
