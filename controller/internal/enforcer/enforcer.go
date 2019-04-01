package enforcer

import (
	"context"
	"fmt"
	"time"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/secretsproxy"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packetprocessor"
	"go.aporeto.io/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
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

	// Run starts the PolicyEnforcer.
	Run(ctx context.Context) error

	// UpdateSecrets -- updates the secrets of running enforcers managed by trireme. Remote enforcers will get the secret updates with the next policy push
	UpdateSecrets(secrets secrets.Secrets) error

	// SetTargetNetworks sets the target network configuration of the controllers.
	SetTargetNetworks(cfg *runtime.Configuration) error

	// Cleanup request a clean up of the controllers.
	CleanUp() error

	DebugInfo
}

// DebugInfo is interface to implement methods to configure datapath packet tracing in the nfqdatapath
type DebugInfo interface {
	//  EnableDatapathPacketTracing will enable tracing of packets received by the datapath for a particular PU. Setting Disabled as tracing direction will stop tracing for the contextID
	EnableDatapathPacketTracing(contextID string, direction packettracing.TracingDirection, interval time.Duration) error

	// EnablePacketTracing enable iptables -j trace for the particular pu and is much wider packet stream.
	EnableIPTablesPacketTracing(ctx context.Context, contextID string, interval time.Duration) error
}

// enforcer holds all the active implementations of the enforcer
type enforcer struct {
	proxy     *applicationproxy.AppProxy
	transport *nfqdatapath.Datapath
	secrets   *secretsproxy.SecretsProxy
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

	if e.secrets != nil {
		if err := e.secrets.Run(ctx); err != nil {
			return err
		}
	}

	return nil
}

// Enforce implements the enforce interface by sending the event to all the enforcers.
func (e *enforcer) Enforce(contextID string, puInfo *policy.PUInfo) error {

	if e.transport != nil {
		if err := e.transport.Enforce(contextID, puInfo); err != nil {
			return fmt.Errorf("Failed to enforce in nfq: %s", err)
		}
	}

	if e.proxy != nil {
		if err := e.proxy.Enforce(context.Background(), contextID, puInfo); err != nil {
			return fmt.Errorf("Failed to enforce in proxy: %s", err)
		}
	}

	if e.secrets != nil {
		if err := e.secrets.Enforce(puInfo); err != nil {
			return fmt.Errorf("Failed to enforce in secrets proxy: %s", err)
		}
	}

	return nil
}

// Unenforce implements the Unenforce interface by sending the event to all the enforcers.
func (e *enforcer) Unenforce(contextID string) error {

	var perr, nerr, serr error
	if e.proxy != nil {
		if perr = e.proxy.Unenforce(context.Background(), contextID); perr != nil {
			zap.L().Error("Failed to unenforce contextID in proxy",
				zap.String("ContextID", contextID),
				zap.Error(perr),
			)
		}
	}

	if e.transport != nil {
		if nerr = e.transport.Unenforce(contextID); nerr != nil {
			zap.L().Error("Failed to unenforce contextID in transport",
				zap.String("ContextID", contextID),
				zap.Error(nerr),
			)
		}
	}

	if e.secrets != nil {
		if serr = e.secrets.Unenforce(contextID); nerr != nil {
			zap.L().Error("Failed to unenforce contextID in transport",
				zap.String("ContextID", contextID),
				zap.Error(nerr),
			)
		}
	}

	if perr != nil || nerr != nil || serr != nil {
		return fmt.Errorf("Failed to unenforce %s %s", perr, nerr)
	}

	return nil
}

func (e *enforcer) SetTargetNetworks(cfg *runtime.Configuration) error {
	return e.transport.SetTargetNetworks(cfg)
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

	if e.secrets != nil {
		if err := e.secrets.UpdateSecrets(secrets); err != nil {
			return err
		}
	}

	return nil
}

// Cleanup implements the cleanup interface. Not much to do here.
func (e *enforcer) CleanUp() error {
	return nil
}

// GetFilterQueue returns the current FilterQueueConfig of the transport path.
func (e *enforcer) GetFilterQueue() *fqconfig.FilterQueue {
	return e.transport.GetFilterQueue()
}

// EnableDatapathPacketTracing implemented the datapath packet tracing
func (e *enforcer) EnableDatapathPacketTracing(contextID string, direction packettracing.TracingDirection, interval time.Duration) error {
	return e.transport.EnableDatapathPacketTracing(contextID, direction, interval)

}

// EnableIPTablesPacketTracing enable iptables -j trace for the particular pu and is much wider packet stream.
func (e *enforcer) EnableIPTablesPacketTracing(ctx context.Context, contextID string, interval time.Duration) error {
	return nil
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
	cfg *runtime.Configuration,
) (Enforcer, error) {

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
		cfg,
	)

	tcpProxy, err := applicationproxy.NewAppProxy(tokenAccessor, collector, puFromContextID, nil, secrets)
	if err != nil {
		return nil, err
	}

	return &enforcer{
		proxy:     tcpProxy,
		transport: transport,
		secrets:   secretsproxy.NewSecretsProxy(),
	}, nil
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
) Enforcer {
	return nfqdatapath.NewWithDefaults(
		serverID,
		collector,
		service,
		secrets,
		mode,
		procMountPoint,
		targetNetworks,
	)
}
