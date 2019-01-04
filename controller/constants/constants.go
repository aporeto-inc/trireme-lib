package constants

const (
	// DefaultProcMountPoint The default proc mountpoint
	DefaultProcMountPoint = "/proc"
	// DefaultAporetoProcMountPoint The aporeto proc mountpoint just in case we are launched with some specific docker config
	DefaultAporetoProcMountPoint = "/aporetoproc"
	// DefaultSecretsPath is the default path for the secrets proxy.
	DefaultSecretsPath = "@secrets"
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

// CompressionTypeMask defines the compression mask.
type CompressionTypeMask uint8

const (
	// CompressionTypeNoneMask mask that identifies compression type none
	CompressionTypeNoneMask CompressionTypeMask = 0x00
	// CompressionTypeV1Mask mask that identifies compression type v1
	CompressionTypeV1Mask CompressionTypeMask = 0x01
	// CompressionTypeV2Mask mask that identifies compression type v2
	CompressionTypeV2Mask CompressionTypeMask = 0x02
	// CompressionTypeMask mask used to check relevant compression types
	CompressionTypeBitMask CompressionTypeMask = 0x03
)

// CompressionTypeToMask returns the mask based on the type
func (ct CompressionType) CompressionTypeToMask() CompressionTypeMask {

	switch ct {
	case CompressionTypeV1:
		return CompressionTypeV1Mask
	case CompressionTypeV2:
		return CompressionTypeV2Mask
	default:
		return CompressionTypeNoneMask
	}
}

// CompressionTypeToMask returns the mask based on the type
func (cm CompressionTypeMask) CompressionMaskToType() CompressionType {

	switch cm {
	case CompressionTypeV1Mask:
		return CompressionTypeV1
	case CompressionTypeV2Mask:
		return CompressionTypeV2
	default:
		return CompressionTypeNone
	}
}

// CompressionTypeToMask returns the mask based on the type
func (cm CompressionTypeMask) ToUint8() uint8 {

	return uint8(cm)
}

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

// API service related constants
const (
	CallbackURIExtension = "/aporeto/oidc/callback"
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
