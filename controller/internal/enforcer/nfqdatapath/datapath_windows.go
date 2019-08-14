// +build windows

package nfqdatapath

import (
	"context"
	"time"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/acls"
	enforcerconstants "go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/nflog"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"go.aporeto.io/trireme-lib/controller/pkg/flowtracking"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packetprocessor"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.aporeto.io/trireme-lib/utils/portcache"
	"go.uber.org/zap"
)

// New will create a new data path structure. It instantiates the data stores
// needed to track sessions. The data path is started with a different call.
// Only required parameters must be provided. Rest a pre-populated with defaults.
func New(
	mutualAuth bool,
	filterQueue *fqconfig.FilterQueue,
	collector collector.EventCollector,
	serverID string,
	validity time.Duration,
	service packetprocessor.PacketProcessor,
	secrets secrets.Secrets,
	mode constants.ModeType,
	procMountPoint string,
	ExternalIPCacheTimeout time.Duration,
	packetLogs bool,
	tokenaccessor tokenaccessor.TokenAccessor,
	puFromContextID cache.DataStore,
	cfg *runtime.Configuration,
) *Datapath {

	if ExternalIPCacheTimeout <= 0 {
		var err error
		ExternalIPCacheTimeout, err = time.ParseDuration(enforcerconstants.DefaultExternalIPTimeout)
		if err != nil {
			ExternalIPCacheTimeout = time.Second
		}
	}

	contextIDFromTCPPort := portcache.NewPortCache("contextIDFromTCPPort")
	contextIDFromUDPPort := portcache.NewPortCache("contextIDFromUDPPort")

	udpSocketWriter, err := GetUDPRawSocket(afinetrawsocket.ApplicationRawSocketMark, "udp")

	if err != nil {
		zap.L().Fatal("Unable to create raw socket for udp packet transmission", zap.Error(err))
	}

	d := &Datapath{
		puFromMark:           cache.NewCache("puFromMark"),
		puFromUser:           cache.NewCache("puFromUser"),
		puFromHash:           cache.NewCache("puFromHash"),
		contextIDFromTCPPort: contextIDFromTCPPort,
		contextIDFromUDPPort: contextIDFromUDPPort,

		puFromContextID: puFromContextID,

		sourcePortConnectionCache: cache.NewCacheWithExpiration("sourcePortConnectionCache", time.Second*24),
		appOrigConnectionTracker:  cache.NewCacheWithExpiration("appOrigConnectionTracker", time.Second*24),
		appReplyConnectionTracker: cache.NewCacheWithExpiration("appReplyConnectionTracker", time.Second*24),
		netOrigConnectionTracker:  cache.NewCacheWithExpiration("netOrigConnectionTracker", time.Second*24),
		netReplyConnectionTracker: cache.NewCacheWithExpiration("netReplyConnectionTracker", time.Second*24),

		udpSourcePortConnectionCache: cache.NewCacheWithExpiration("udpSourcePortConnectionCache", time.Second*60),
		udpAppOrigConnectionTracker:  cache.NewCacheWithExpiration("udpAppOrigConnectionTracker", time.Second*60),
		udpAppReplyConnectionTracker: cache.NewCacheWithExpiration("udpAppReplyConnectionTracker", time.Second*60),
		udpNetOrigConnectionTracker:  cache.NewCacheWithExpiration("udpNetOrigConnectionTracker", time.Second*60),
		udpNetReplyConnectionTracker: cache.NewCacheWithExpiration("udpNetReplyConnectionTracker", time.Second*60),
		udpNatConnectionTracker:      cache.NewCacheWithExpiration("udpNatConnectionTracker", time.Second*60),
		udpFinPacketTracker:          cache.NewCacheWithExpiration("udpFinPacketTracker", time.Second*60),

		packetTracingCache:     cache.NewCache("PacketTracingCache"),
		targetNetworks:         acls.NewACLCache(),
		ExternalIPCacheTimeout: ExternalIPCacheTimeout,
		filterQueue:            filterQueue,
		mutualAuthorization:    mutualAuth,
		service:                service,
		collector:              collector,
		tokenAccessor:          tokenaccessor,
		secrets:                secrets,
		ackSize:                secrets.AckSize(),
		mode:                   mode,
		procMountPoint:         procMountPoint,
		packetLogs:             packetLogs,
		udpSocketWriter:        udpSocketWriter,
		puToPortsMap:           map[string]map[string]bool{},
		puCountersChannel:      make(chan *pucontext.PUContext, 220),
	}

	if err = d.SetTargetNetworks(cfg); err != nil {
		zap.L().Error("Error adding target networks to the ACLs", zap.Error(err))
	}

	d.nflogger = nflog.NewNFLogger(11, 10, d.puContextDelegate, collector)

	if mode != constants.RemoteContainer {
		go d.autoPortDiscovery()
	}

	return d
}

// NewWithDefaults create a new data path with most things used by default
func NewWithDefaults(
	serverID string,
	collector collector.EventCollector,
	service packetprocessor.PacketProcessor,
	secrets secrets.Secrets,
	mode constants.ModeType,
	procMountPoint string,
	targetNetworks []string,
) *Datapath {

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
	defaultPacketLogs := false

	tokenAccessor, err := tokenaccessor.New(serverID, defaultValidity, secrets)
	if err != nil {
		zap.L().Fatal("Cannot create a token engine", zap.Error(err))
	}

	puFromContextID := cache.NewCache("puFromContextID")

	e := New(
		defaultMutualAuthorization,
		defaultFQConfig,
		collector,
		serverID,
		defaultValidity,
		service,
		secrets,
		mode,
		procMountPoint,
		defaultExternalIPCacheTimeout,
		defaultPacketLogs,
		tokenAccessor,
		puFromContextID,
		&runtime.Configuration{TCPTargetNetworks: targetNetworks},
	)

	conntrackClient, err := flowtracking.NewClient(context.Background())
	if err != nil {
		return nil
	}
	e.conntrack = conntrackClient

	return e
}
