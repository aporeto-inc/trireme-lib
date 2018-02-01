package enforcer

import (
	"context"
	"fmt"
	"time"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/controller/constants"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/tcp"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/nfqdatapath"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/controller/internal/portset"
	"github.com/aporeto-inc/trireme-lib/controller/packetprocessor"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

// A Enforcer is an implementation of the enforcer datapath. The interface
// can be implemented by one or multiple datapaths.
type Enforcer interface {

	// Enforce starts enforcing policies for the given policy.PUInfo.
	Enforce(contextID string, puInfo *policy.PUInfo) error

	// Unenforce stops enforcing policy for the given IP.
	Unenforce(contextID string) error

	// GetFilterQueue returns the current FilterQueueConfig.
	GetFilterQueue() *fqconfig.FilterQueue

	// GetPortSetInstance returns nil for the proxy
	GetPortSetInstance() portset.PortSet

	// Run starts the PolicyEnforcer.
	Run(ctx context.Context) error

	// UpdateSecrets -- updates the secrets of running enforcers managed by trireme. Remote enforcers will get the secret updates with the next policy push
	UpdateSecrets(secrets secrets.Secrets) error
}

// enforcer holds all the active implementations of the enforcer
type enforcer struct {
	proxy     *tcp.Proxy
	transport *nfqdatapath.Datapath
}

// Run implements the run interfaces and runs the individual data paths
func (e *enforcer) Run(ctx context.Context) error {

	if e.proxy != nil {
		if err := e.proxy.Run(ctx); err != nil {
			return err
		}
	}

	if e.transport != nil {
		if err := e.transport.Run(ctx); err != nil {
			return err
		}
	}

	return nil
}

// Enforce implements the enforce interface by sending the event to all the enforcers.
func (e *enforcer) Enforce(contextID string, puInfo *policy.PUInfo) error {

	if e.proxy != nil {
		if err := e.proxy.Enforce(contextID, puInfo); err != nil {
			return fmt.Errorf("Failed to enforce in proxy %s", err.Error())
		}
	}

	if e.transport != nil {
		if err := e.transport.Enforce(contextID, puInfo); err != nil {
			return fmt.Errorf("Failed to enforce in nfq %s", err.Error())
		}
	}

	return nil
}

// Unenforce implements the Unenforce interface by sending the event to all the enforcers.
func (e *enforcer) Unenforce(contextID string) error {

	var perr, nerr error
	if e.proxy != nil {
		if perr = e.proxy.Unenforce(contextID); perr != nil {
			zap.L().Error("Failed to unenforce contextID in proxy",
				zap.String("ContextID", contextID),
				zap.Error(perr),
			)
		}
	}

	if e.transport != nil {
		if nerr = e.transport.Unenforce(contextID); nerr != nil {
			zap.L().Error("Failed to unenforce contextID in proxy",
				zap.String("ContextID", contextID),
				zap.Error(nerr),
			)
		}
	}

	if perr != nil || nerr != nil {
		return fmt.Errorf("Failed to unenforce %s %s", perr, nerr)
	}

	return nil
}

// Updatesecrets updates the secrets of the enforcers
func (e *enforcer) UpdateSecrets(secrets secrets.Secrets) error {
	if e.proxy != nil {
		if err := e.proxy.UpdateSecrets(secrets); err != nil {
			return err
		}
	}

	if e.transport != nil {
		if err := e.transport.UpdateSecrets(secrets); err != nil {
			return err
		}
	}

	return nil
}

// GetFilterQueue returns the current FilterQueueConfig of the transport path.
func (e *enforcer) GetFilterQueue() *fqconfig.FilterQueue {
	return e.transport.GetFilterQueue()
}

// GetPortSetInstance returns the port instance of the transport datapath
func (e *enforcer) GetPortSetInstance() portset.PortSet {
	return e.transport.GetPortSetInstance()
}

// New returns a new policy enforcer that implements both the data paths.
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

	tokenAccessor, err := tokenaccessor.New(serverID, validity, secrets)
	if err != nil {
		zap.L().Fatal("Cannot create a token engine")
	}

	puFromContextID := cache.NewCache("puFromContextID")

	transport := nfqdatapath.New(
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
		tokenAccessor,
		puFromContextID,
	)

	tcpProxy := tcp.NewProxy(":5000", true, false, tokenAccessor, collector, puFromContextID, mutualAuthorization)

	return &enforcer{
		proxy:     tcpProxy,
		transport: transport,
	}
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
	return nfqdatapath.NewWithDefaults(
		serverID,
		collector,
		service,
		secrets,
		mode,
		procMountPoint,
	)
}
