package constants

import (
	"path/filepath"
	"time"
)

const (
	// DefaultProcMountPoint The default proc mountpoint
	DefaultProcMountPoint = "/proc"
	// DefaultAporetoProcMountPoint The aporeto proc mountpoint just in case we are launched with some specific docker config
	DefaultAporetoProcMountPoint = "/aporetoproc"
	// DefaultSecretsPath is the default path for the secrets proxy.
	DefaultSecretsPath = "@secrets"

	// EnforcerdCleanerName is the path of the cleaner script.
	EnforcerdCleanerName = "cleaner"

	// DefaultEnforcerdCleanerPath is the default path of the cleaner.  For now set this to
	// /sbin/cleaner.  Note that the cleaner path is set via the container master enforcer but
	// it is ultimately run in the host and not in the container. Prior to defender integrations
	// we used the same path /sbin/cleaner in the host and /sbin/cleaner in the container and it
	// worked.  Now, with the defender integration we use a tarball to install the enforcer and
	// all the binaries, and it may install anywhere on the host, as specified by the defender
	// installer.  The container does not know where it was installed. Furthermore, we no longer
	// install via .deb or .rpm files so there is no system files installed, and cleaner will not
	// be found in /sbin/cleaner when installed via the defender bundle installer.  So a new
	// startup flag is defined now, `--cleaner-path` and environment variable
	// `ENFORCED_CLEANER_PATH` that defender can use to tell us where it installed the
	// cleaner. With this, the container enforcer can properly set the cleaner path in the
	// cgroups v1 release_agent.
	//
	// TLDR; We now use /enforcerd-tools/cleaner in the container, and it will be installed in
	// /path/to/install/ation/dir/enforcerd-tools/cleaner in the host.  container enforcer will
	// tell cgroup sub-system to use /enforcerd-tools/cleaner but cgroups executes it on the
	// host and can't find it here. Ergo, it won't work on a defender install this way.
	//
	// TODO - fix this so cleaner can be installed by defender and the installation path can be
	// discovered by container enforcer
	DefaultEnforcerdCleanerPath = "/sbin/cleaner"

	// RemoteEnforcerBuildName is the name of the remote enforcer binary we will build and deploy
	RemoteEnforcerBuildName = "remoteenforcerd"

	// RemoteEnforcerSrcName is the name of the original copy of the remote enforcer binary
	RemoteEnforcerSrcName = "remoteenforcer"
)

const (
	// DefaultRemoteArg is the default arguments for a remote enforcer
	DefaultRemoteArg = "enforce"
)

const (

	// EnvMountPoint is an environment variable which will contain the mount point
	EnvMountPoint = "TRIREME_ENV_PROC_MOUNTPOINT"

	// EnvEnforcerType is an environment variable which will indicate what enforcer type we want to use
	EnvEnforcerType = "TRIREME_ENV_ENFORCER_TYPE"

	// EnvContextSocket stores the path to the context specific socket
	EnvContextSocket = "TRIREME_ENV_SOCKET_PATH"

	// EnvStatsChannel stores the path to the stats channel
	EnvStatsChannel = "TRIREME_ENV_STATS_CHANNEL_PATH"

	// EnvDebugChannel stores the path to the debug channel
	EnvDebugChannel = "TRIREME_ENV_DEBUG_CHANNEL_PATH"

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

	// EnvLogID store the context Id for the log file to be used.
	EnvLogID = "TRIREME_ENV_LOG_ID"

	// EnvCompressedTags stores whether we should be using compressed tags.
	EnvCompressedTags = "TRIREME_ENV_COMPRESSED_TAGS"

	// EnvEnforcerdToolsDir is the path to the /enforcerd-tools directory so remote enforcerd can find tools.
	EnvEnforcerdToolsDir = "TRIREME_ENV_ENFORCERD_TOOLS_DIR"

	// EnvEnforcerdNFQueues exports the number of nfqueues to remote enforcer
	EnvEnforcerdNFQueues = "TRIREME_ENV_NUM_NFQUEUES"
)

// ModeType defines the mode of the enforcement and supervisor.
type ModeType int

const (
	// RemoteContainer indicates that the Supervisor is implemented in the
	// container namespace
	RemoteContainer ModeType = iota
	// LocalServer indicates that the Supervisor applies to Linux processes
	LocalServer
	// LocalEnvoyAuthorizer indicates to use a local envoyproxy as enforcer/authorizer
	LocalEnvoyAuthorizer
	// RemoteContainerEnvoyAuthorizer indicates to use the envoyproxy enforcer/authorizer for containers
	RemoteContainerEnvoyAuthorizer
)

// LogLevel corresponds to log level of any logger. eg: zap.
type LogLevel string

// LogOptions
const (
	// OptionLogLevel represents the log-level
	OptionLogLevel = "log-level"
	// OptionLogFormat represents the log-format
	OptionLogFormat = "log-format"
	// OptionLogFilePath represents the log location path
	OptionLogFilePath = "log-file-path"
)

// Various log levels.
const (
	Info  LogLevel = "Info"
	Debug LogLevel = "Debug"
	Trace LogLevel = "Trace"
	Error LogLevel = "Error"
	Warn  LogLevel = "Warn"
)

// API service related constants
const (
	CallbackURIExtension = "/aporeto/oidc/callback"
)

// Protocol constants
const (
	TCPProtoNum    = "6"
	UDPProtoNum    = "17"
	TCPProtoString = "TCP"
	UDPProtoString = "UDP"
	AllProtoString = "ALL"
)

//MaxICMPCodes constant puts the maximum number of codes that can be put in a single string
const MaxICMPCodes = 25

// Channel variables
var (
	StatsChannel string
	DebugChannel string
)

// PortNumberLabelString is the label to use for port numbers
const (
	PortNumberLabelString = "@sys:port"
)

// ControllerLabelString is the label to use for control planes
const (
	ControllerLabelString = "$controller"
)

// Token and cache default validities. These have performance implications.
// The faster the datapath issues new tokens it affects performance. However,
// making it too slow can potentially allow reuse of the tokens. The
// token issuance rate must be always faster than the expiration rate.
const (
	// SynTokenRefreshTime determines how often the data path creates new tokens.
	SynTokenRefreshTime = 5 * time.Minute
	// SynTokenValidity determines how long after the tokens are considered valid.
	SynTokenValidity = 10 * time.Minute
)

// SocketsPath is used to find the socket file corresponding to the container
var SocketsPath string

// RemoteEnforcerPath sets the path of the remote enforcer
var RemoteEnforcerPath string

// ConfigureRemoteEnforcerPath updates the remote enforcer path
func ConfigureRemoteEnforcerPath(path string) {
	RemoteEnforcerPath = filepath.Join(path, RemoteEnforcerBuildName)
}

// ConfigureSocketsPath updates the sockets path
func ConfigureSocketsPath(sockPath string) {
	SocketsPath = sockPath
	StatsChannel = filepath.Join(sockPath, "statschannel.sock")
	DebugChannel = filepath.Join(sockPath, "debugchannel.sock")
}

// Mark used by the proxies/ping to bypass trap rules.
const (
	ProxyMarkInt = 0x40
	ProxyMark    = "0x40"
)

const (
	// ChainPrefix represents trireme chain prefix.
	ChainPrefix = "TRI-"
)
