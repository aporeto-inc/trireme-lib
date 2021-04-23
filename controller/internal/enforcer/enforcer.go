package enforcer

import (
	"context"
	"fmt"
	"time"

	"github.com/blang/semver"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/envoyauthorizer"
	"go.aporeto.io/gaia"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"

	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/ephemeralkeys"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/ebpf"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/controller/runtime"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

// A Enforcer is an implementation of the enforcer datapath. The interface
// can be implemented by one or multiple datapaths.
type Enforcer interface {

	// Enforce starts enforcing policies for the given policy.PUInfo.
	Enforce(ctx context.Context, contextID string, puInfo *policy.PUInfo) error

	// Unenforce stops enforcing policy for the given IP.
	Unenforce(ctx context.Context, contextID string) error

	// GetFilterQueue returns the current FilterQueueConfig.
	GetFilterQueue() fqconfig.FilterQueue

	// GetBPFObject returns the bpf pobject
	GetBPFObject() ebpf.BPFModule

	// Run starts the PolicyEnforcer.
	Run(ctx context.Context) error

	// UpdateSecrets -- updates the secrets of running enforcers managed by trireme. Remote enforcers will get the secret updates with the next policy push
	UpdateSecrets(secrets secrets.Secrets) error

	// SetTargetNetworks sets the target network configuration of the controllers.
	SetTargetNetworks(cfg *runtime.Configuration) error

	// SetLogLevel sets log level.
	SetLogLevel(level constants.LogLevel) error

	// Cleanup request a clean up of the controllers.
	CleanUp() error

	// GetServiceMeshType returns the serviceMeshType
	GetServiceMeshType() policy.ServiceMesh

	DebugInfo
}

// DebugInfo is interface to implement methods to configure datapath packet tracing in the nfqdatapath
type DebugInfo interface {
	//  EnableDatapathPacketTracing will enable tracing of packets received by the datapath for a particular PU. Setting Disabled as tracing direction will stop tracing for the contextID
	EnableDatapathPacketTracing(ctx context.Context, contextID string, direction packettracing.TracingDirection, interval time.Duration) error

	// EnablePacketTracing enable iptables -j trace for the particular pu and is much wider packet stream.
	EnableIPTablesPacketTracing(ctx context.Context, contextID string, interval time.Duration) error

	// Ping runs ping based on the given config.
	Ping(ctx context.Context, contextID string, pingConfig *policy.PingConfig) error

	// DebugCollect collects debug information, such as packet capture
	DebugCollect(ctx context.Context, contextID string, debugConfig *policy.DebugConfig) error
}

// enforcer holds all the active implementations of the enforcer
type enforcer struct {
	proxy     *applicationproxy.AppProxy
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
func (e *enforcer) Enforce(ctx context.Context, contextID string, puInfo *policy.PUInfo) error {
	if e.transport != nil {
		if err := e.transport.Enforce(ctx, contextID, puInfo); err != nil {
			return fmt.Errorf("unable to enforce in nfq: %s", err)
		}
	}

	if e.proxy != nil {
		// NOTE: Passing ctx here breaks proxy. Root cause unknown for now
		if err := e.proxy.Enforce(context.Background(), contextID, puInfo); err != nil {
			return fmt.Errorf("unable to enforce in proxy: %s", err)
		}
	}

	return nil
}

// Unenforce implements the Unenforce interface by sending the event to all the enforcers.
func (e *enforcer) Unenforce(ctx context.Context, contextID string) error {

	var perr, nerr, serr error

	if e.proxy != nil {
		if perr = e.proxy.Unenforce(ctx, contextID); perr != nil {
			zap.L().Error("Failed to unenforce contextID in proxy",
				zap.String("ContextID", contextID),
				zap.Error(perr),
			)
		}
	}

	if e.transport != nil {
		if nerr = e.transport.Unenforce(ctx, contextID); nerr != nil {
			zap.L().Error("Failed to unenforce contextID in transport",
				zap.String("ContextID", contextID),
				zap.Error(nerr),
			)
		}
	}

	if perr != nil || nerr != nil || serr != nil {
		return fmt.Errorf("Failed to unenforce. proxy: %s transport: %s secret: %s", perr, nerr, serr)
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

	return nil
}

// SetLogLevel sets log level.
func (e *enforcer) SetLogLevel(level constants.LogLevel) error {

	if e.transport != nil {
		if err := e.transport.SetLogLevel(level); err != nil {
			return err
		}
	}

	return nil
}

// Cleanup implements the cleanup interface.
func (e *enforcer) CleanUp() error {
	if e.transport != nil {
		return e.transport.CleanUp()
	}
	return nil
}

//GetBPFObject returns the bpf object
func (e *enforcer) GetBPFObject() ebpf.BPFModule {
	return e.transport.GetBPFObject()
}

// GetServiceMeshType returns the serviceMesh type
func (e *enforcer) GetServiceMeshType() policy.ServiceMesh {
	return e.transport.GetServiceMeshType()
}

// GetFilterQueue returns the current FilterQueueConfig of the transport path.
func (e *enforcer) GetFilterQueue() fqconfig.FilterQueue {
	return e.transport.GetFilterQueue()
}

// EnableDatapathPacketTracing implemented the datapath packet tracing
func (e *enforcer) EnableDatapathPacketTracing(ctx context.Context, contextID string, direction packettracing.TracingDirection, interval time.Duration) error {
	return e.transport.EnableDatapathPacketTracing(ctx, contextID, direction, interval)

}

// EnableIPTablesPacketTracing enable iptables -j trace for the particular pu and is much wider packet stream.
func (e *enforcer) EnableIPTablesPacketTracing(ctx context.Context, contextID string, interval time.Duration) error {
	return nil
}

// Ping runs ping to the given config.
func (e *enforcer) Ping(ctx context.Context, contextID string, pingConfig *policy.PingConfig) error {

	srv := policy.ServiceL3
	sctx, sdata, err := e.proxy.ServiceData(
		contextID,
		pingConfig.IP,
		int(pingConfig.Port),
		pingConfig.ServiceAddresses)
	if err == nil {
		srv = sdata.ServiceObject.Type
	}

	switch pingConfig.Mode {
	case gaia.ProcessingUnitRefreshPingModeAuto:
		switch srv {
		case policy.ServiceHTTP, policy.ServiceTCP:
			return e.proxy.Ping(ctx, contextID, sctx, sdata, pingConfig)
		default:
			return e.transport.Ping(ctx, contextID, pingConfig)
		}

	case gaia.ProcessingUnitRefreshPingModeL3:
		return e.transport.Ping(ctx, contextID, pingConfig)

	case gaia.ProcessingUnitRefreshPingModeL4, gaia.ProcessingUnitRefreshPingModeL7:
		return e.proxy.Ping(ctx, contextID, sctx, sdata, pingConfig)

	default:
		return e.transport.Ping(ctx, contextID, pingConfig)
	}
}

func (e *enforcer) DebugCollect(ctx context.Context, contextID string, debugConfig *policy.DebugConfig) error {
	// this is handled in remoteenforcer
	return nil
}

// New returns a new policy enforcer that implements both the data paths.
func New(
	mutualAuthorization bool,
	fqConfig fqconfig.FilterQueue,
	collector collector.EventCollector,
	secrets secrets.Secrets,
	serverID string,
	validity time.Duration,
	mode constants.ModeType,
	procMountPoint string,
	externalIPCacheTimeout time.Duration,
	packetLogs bool,
	cfg *runtime.Configuration,
	tokenIssuer common.ServiceTokenIssuer,
	isBPFEnabled bool,
	agentVersion semver.Version,
	serviceMeshType policy.ServiceMesh,
) (Enforcer, error) {
	if mode == constants.RemoteContainerEnvoyAuthorizer || mode == constants.LocalEnvoyAuthorizer {
		return envoyauthorizer.NewEnvoyAuthorizerEnforcer(mode, collector, externalIPCacheTimeout, secrets, tokenIssuer)
	}

	tokenAccessor, err := tokenaccessor.New(serverID, validity, secrets)

	if err != nil {
		zap.L().Fatal("Cannot create a token engine")
	}

	datapathKeypair, err := ephemeralkeys.NewWithRenewal()
	if err != nil {
		zap.L().Fatal("Cannot create a ephemeral key pair", zap.Error(err))
	}

	puFromContextID := cache.NewCache("puFromContextID")

	transport := nfqdatapath.New(
		mutualAuthorization,
		fqConfig,
		collector,
		serverID,
		validity,
		secrets,
		mode,
		procMountPoint,
		externalIPCacheTimeout,
		packetLogs,
		tokenAccessor,
		puFromContextID,
		cfg,
		isBPFEnabled,
		agentVersion,
		serviceMeshType,
	)
	var appProxy *applicationproxy.AppProxy

	if serviceMeshType == policy.None {
		appProxy, err = applicationproxy.NewAppProxy(tokenAccessor, collector, puFromContextID, secrets, tokenIssuer, datapathKeypair, agentVersion)
		if err != nil {
			return nil, fmt.Errorf("App proxy %s", err)
		}
	}

	return &enforcer{
		proxy:     appProxy,
		transport: transport,
	}, nil
}
