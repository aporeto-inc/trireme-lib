package constants

const (
	//DefaultProxyPort  the default port the l4 proxy listens on
	DefaultProxyPort = "5000"
	//DefaultProcMountPoint The default proc mountpoint
	DefaultProcMountPoint = "/proc"
	//DefaultAporetoProcMountPoint The aporeto proc mountpoint just in case we are launched with some specific docker config
	DefaultAporetoProcMountPoint = "/aporetoproc"
)

const (
	// DefaultRemoteArg is the default arguments for a remote enforcer
	DefaultRemoteArg = "enforce"
	// DefaultConnMark is the default conn mark for all data packets
	DefaultConnMark = uint32(0xEEEE)
)

const (

	// EnvMountPoint is an environment variable which will contain the mount point
	EnvMountPoint = "TRIREME_ENV_PROC_MOUNTPOINT"

	// EnvContextSocket stores the path to the context specific socket
	EnvContextSocket = "TRIREME_ENV_SOCKET_PATH"

	// EnvStatsChannel stores the path to the stats channel
	EnvStatsChannel = "TRIREME_ENV_STATS_CHANNEL_PATH"

	// EnvRPCClientSecret is the secret used between RPC client/server
	EnvRPCClientSecret = "TRIREME_ENV_SECRET"

	// EnvStatsSecret is the secret to be used for the stats channel
	EnvStatsSecret = "TRIREME_ENV_STATS_SECRET"

	// EnvContainerPID is the PID of the container
	EnvContainerPID = "TRIREME_ENV_CONTAINER_PID"

	// EnvNSPath is the path of the network namespace
	EnvNSPath = "TRIREME_ENV_NS_PATH"

	// EnvNsenterErrorState stores the error state as reported by remote enforcer
	EnvNsenterErrorState = "TRIREME_ENV_NSENTER_ERROR_STATE"

	// EnvNsenterLogs stores the logs as reported by remote enforcer
	EnvNsenterLogs = "TRIREME_ENV_NSENTER_LOGS"

	// EnvLogLevel store the log level to be used.
	EnvLogLevel = "TRIREME_ENV_LOG_LEVEL"

	// EnvLogFormat store the log format to be used.
	EnvLogFormat = "TRIREME_ENV_LOG_FORMAT"

	// EnvLogToConsole specifies if logs should be sent out to console.
	EnvLogToConsole = "TRIREME_ENV_LOG_TO_CONSOLE"

	// EnvLogToConsoleEnable specifies value to enable logging to console.
	EnvLogToConsoleEnable = "1"

	// EnvLogID store the context Id for the log file to be used.
	EnvLogID = "TRIREME_ENV_LOG_ID"

	// EnvCompressedTags stores whether we should be using compressed tags.
	EnvCompressedTags = "TRIREME_ENV_COMPRESSED_TAGS"
)

// ModeType defines the mode of the enforcement and supervisor.
type ModeType int

const (
	// RemoteContainer indicates that the Supervisor is implemented in the
	// container namespace
	RemoteContainer ModeType = iota
	// LocalServer indicates that the Supervisor applies to Linux processes
	LocalServer
	// Sidecar indicates the controller to be in sidecar mode
	Sidecar
)

// CompressionType defines the compression used.
type CompressionType string

const (
	// CompressionTypeNone implies no compression
	CompressionTypeNone CompressionType = ""
	// CompressionTypeV1 is version 1 of compression
	CompressionTypeV1 CompressionType = "1"
	// CompressionTypeV2 is version 2 of compression
	CompressionTypeV2 CompressionType = "2"
)

const (
	// CompressedTagLengthV1 is version 1 length of tags
	CompressedTagLengthV1 int = 12

	// CompressedTagLengthV2 is version 2 length of tags
	CompressedTagLengthV2 int = 4
)

// CompressionTypeToTagLength converts CompressionType to length.
func CompressionTypeToTagLength(t CompressionType) int {

	if t == CompressionTypeNone {
		return 0
	}

	if t == CompressionTypeV1 {
		return CompressedTagLengthV1
	}

	return CompressedTagLengthV2
}

// String2CompressionType is a helper to convert string to compression type
func String2CompressionType(s string) CompressionType {
	if s == string(CompressionTypeV1) {
		return CompressionTypeV1
	}
	if s == string(CompressionTypeV2) {
		return CompressionTypeV2
	}
	return CompressionTypeNone
}
