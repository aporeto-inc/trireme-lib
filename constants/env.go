package constants

const (

	// AporetoEnvMountPoint is an environment variable which will contain the mount point
	AporetoEnvMountPoint = "APORETO_ENV_PROC_MOUNTPOINT"

	// AporetoEnvContextSocket stores the path to the context specific socket
	AporetoEnvContextSocket = "APORETO_ENV_SOCKET_PATH"

	// AporetoEnvStatsChannel stores the path to the stats channel
	AporetoEnvStatsChannel = "APORETO_ENV_STATS_CHANNEL_PATH"

	// AporetoEnvRPCClientSecret is the secret used between RPC client/server
	AporetoEnvRPCClientSecret = "APORETO_ENV_SECRET"

	// AporetoEnvStatsSecret is the secret to be used for the stats channel
	AporetoEnvStatsSecret = "APORETO_ENV_STATS_SECRET"

	// AporetoEnvContainerPID is the PID of the container
	AporetoEnvContainerPID = "APORETO_ENV_CONTAINER_PID"

	// AporetoEnvNSPath is the path of the network namespace
	AporetoEnvNSPath = "APORETO_ENV_NS_PATH"

	// AporetoEnvNsenterErrorState stores the error state as reported by remote enforcer
	AporetoEnvNsenterErrorState = "APORETO_ENV_NSENTER_ERROR_STATE"

	// AporetoEnvNsenterLogs stores the logs as reported by remote enforcer
	AporetoEnvNsenterLogs = "APORETO_ENV_NSENTER_LOGS"

	// AporetoEnvLogLevel store the log level to be used.
	AporetoEnvLogLevel = "APORETO_ENV_LOG_LEVEL"

	// AporetoEnvLogFormat store the log format to be used.
	AporetoEnvLogFormat = "APORETO_ENV_LOG_FORMAT"

	// AporetoEnvLogToConsole specifies if logs should be sent out to console.
	AporetoEnvLogToConsole = "APORETO_ENV_LOG_TO_CONSOLE"

	// AporetoEnvLogToConsoleEnable specifies value to enable logging to console.
	AporetoEnvLogToConsoleEnable = "1"

	// AporetoEnvLogID store the context Id for the log file to be used.
	AporetoEnvLogID = "APORETO_ENV_LOG_ID"
)
