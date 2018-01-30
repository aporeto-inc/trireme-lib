package enforcer

import (
	"time"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/datapath"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/controller/packetprocessor"
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
	packetLogs bool,
) Enforcer {
	return datapath.New(
		mutualAuthorization,
		fqConfig,
		collector,
		serverID,
		validity,
		service,
		secrets,
		mode,
		procMountPoint,
		externalIPCacheTimeout,
		packetLogs,
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
) Enforcer {
	return datapath.NewWithDefaults(
		serverID,
		collector,
		service,
		secrets,
		mode,
		procMountPoint,
	)
}
