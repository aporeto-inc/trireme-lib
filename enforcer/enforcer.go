package enforcer

import (
	"time"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/datapath"
	"github.com/aporeto-inc/trireme-lib/enforcer/datapath/proxy/tcp"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
	"go.uber.org/zap"
)

// NewWithDefaults create a new data path with most things used by default
func NewWithDefaults(
	serverID string,
	collector collector.EventCollector,
	service PacketProcessor,
	secrets secrets.Secrets,
	mode constants.ModeType,
	procMountPoint string,
) PolicyEnforcer {

	if collector == nil {
		zap.L().Fatal("Collector must be given to NewDefaultDatapathEnforcer")
	}

	defaultMutualAuthorization := false
	defaultFQConfig := fqconfig.NewFilterQueueWithDefaults()
	defaultValidity := time.Hour * 8760
	defaultExternalIPCacheTimeout, err := time.ParseDuration(DefaultExternalIPTimeout)
	if err != nil {
		defaultExternalIPCacheTimeout = time.Second
	}

	//passing d here since we can reuse the caches and func here rather than redefining them again in proxy.
	return datapath.New(
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
		tcp.NewProxy(":5000", true, false, d),
	)
}
