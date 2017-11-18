package enforcer

import (
	"time"

	"github.com/aporeto-inc/trireme-lib/cache"
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/datapath"
	"github.com/aporeto-inc/trireme-lib/enforcer/datapath/proxy/tcp"
	"github.com/aporeto-inc/trireme-lib/enforcer/datapath/tokenprocessor"
	"github.com/aporeto-inc/trireme-lib/enforcer/packetprocessor"
	"github.com/aporeto-inc/trireme-lib/enforcer/policyenforcer"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/tokens"
	"go.uber.org/zap"
)

// New returns a new policy enforcer
func New(
	mutualAuthorization bool,
	fqConfig *fqconfig.FilterQueue,
	collector collector.EventCollector,
	service packetprocessor.PacketProcessor,
	secrets secrets.Secrets,
	serverID string,
	validity time.Duration,
	mode constants.ModeType,
	procMountPoint string,
	externalIPCacheTimeout time.Duration,
) policyenforcer.Enforcer {

	tokenEngine, err := tokens.NewJWT(validity, serverID, secrets)
	if err != nil {
		zap.L().Fatal("Unable to create TokenEngine in enforcer", zap.Error(err))
	}
	tokenProcessor := tokenprocessor.New(tokenEngine)
	contextTracker := cache.NewCache("contextTracker")
	return datapath.New(
		mutualAuthorization,
		fqConfig,
		collector,
		tokenProcessor,
		contextTracker,
		tokenEngine,
		service,
		secrets,
		mode,
		procMountPoint,
		externalIPCacheTimeout,
		tcp.NewProxy(":5000", true, false, tokenProcessor, collector, contextTracker, mutualAuthorization),
	)
}

// NewWithDefaults create a new data path with most things used by default
func NewWithDefaults(
	serverID string,
	collector collector.EventCollector,
	service packetprocessor.PacketProcessor,
	secrets secrets.Secrets,
	mode constants.ModeType,
	procMountPoint string,
) policyenforcer.Enforcer {

	if collector == nil {
		zap.L().Fatal("Collector must be given to NewDefaultDatapathEnforcer")
	}

	defaultMutualAuthorization := false
	defaultFQConfig := fqconfig.NewFilterQueueWithDefaults()
	defaultValidity := time.Hour * 8760
	defaultExternalIPCacheTimeout, err := time.ParseDuration(enforcerconstants.DefaultExternalIPTimeout)
	if err != nil {
		defaultExternalIPCacheTimeout = time.Second
	}

	//passing d here since we can reuse the caches and func here rather than redefining them again in proxy.
	return New(
		defaultMutualAuthorization,
		defaultFQConfig,
		collector,
		service,
		secrets,
		serverID,
		defaultValidity,
		mode,
		procMountPoint,
		defaultExternalIPCacheTimeout,
	)
}
