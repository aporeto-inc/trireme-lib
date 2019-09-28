package envoyauthorizer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/apiauth"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
	enforcerconstants "go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/envoyauthorizer/envoyproxy"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/metadata"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

// Enforcer implements the Enforcer interface as an envoy authorizer
// and starts envoy external authz filter gRPC servers for enforcement.
type Enforcer struct {
	mode                   constants.ModeType
	collector              collector.EventCollector
	externalIPCacheTimeout time.Duration
	secrets                secrets.Secrets
	tokenIssuer            common.ServiceTokenIssuer

	registry     *serviceregistry.Registry
	puContexts   cache.DataStore
	clients      cache.DataStore
	systemCAPool *x509.CertPool

	auth     *apiauth.Processor
	metadata *metadata.Client
	sync.RWMutex
}

// envoyAuthzServers, envoy servers used my enforcer
type envoyServers struct {
	ingress *envoyproxy.AuthServer
	egress  *envoyproxy.AuthServer
	sds     *envoyproxy.SdsServer
}

// NewEnvoyAuthorizerEnforcer creates a new envoy authorizer
func NewEnvoyAuthorizerEnforcer(mode constants.ModeType, eventCollector collector.EventCollector, externalIPCacheTimeout time.Duration, secrets secrets.Secrets, tokenIssuer common.ServiceTokenIssuer) (*Enforcer, error) {
	// abort if this is not the right mode
	if mode != constants.RemoteContainerEnvoyAuthorizer && mode != constants.LocalEnvoyAuthorizer {
		return nil, fmt.Errorf("enforcer mode type must be either RemoteContainerEnvoyAuthorizer or LocalEnvoyAuthorizer, got: %d", mode)
	}

	// same logic as in the nfqdatapath
	if externalIPCacheTimeout <= 0 {
		var err error
		externalIPCacheTimeout, err = time.ParseDuration(enforcerconstants.DefaultExternalIPTimeout)
		if err != nil {
			externalIPCacheTimeout = time.Second
		}
	}

	// same logic as in app proxy
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	if ok := systemPool.AppendCertsFromPEM(secrets.PublicSecrets().CertAuthority()); !ok {
		return nil, fmt.Errorf("error while adding provided CA")
	}
	// TODO: systemPool needs the same treatment as the AppProxy and a `processCertificateUpdates` and `expandCAPool` implementation as well
	fmt.Println("ABHI ** New envoy auth")
	return &Enforcer{
		mode:                   mode,
		collector:              eventCollector,
		externalIPCacheTimeout: externalIPCacheTimeout,
		secrets:                secrets,
		tokenIssuer:            tokenIssuer,
		registry:               serviceregistry.NewServiceRegistry(),
		puContexts:             cache.NewCache("puContexts"),
		clients:                cache.NewCache("clients"),
		// auth:                   apiauth.New(puContexts, registry, secrets),
		// metadata:               metadata.NewClient(puContext, registry, tokenIssuer),
	}, nil
}

// Secrets implements the LockedSecrets
func (e *Enforcer) Secrets() (secrets.Secrets, func()) {
	e.RLock()
	return e.secrets, e.RUnlock
}

// Enforce starts enforcing policies for the given policy.PUInfo.
// here we do the following:
// 1. create a new PU.
// 2. create a PUcontext as this will be used in auth code.
// 3. If envoy servers are not present then create all 3 envoy servers.
// 4. If the servers are already present under policy update then update the service certs.
func (e *Enforcer) Enforce(contextID string, puInfo *policy.PUInfo) error {
	e.Lock()
	defer e.Unlock()

	zap.L().Info("ENforce for the envoy remoteEnforcer")
	// here we 1st need to create a PuContext, as the PU context will derive the
	// serviceCtxt which will be used by the authorizer to determine the policyInfo.

	pu, err := pucontext.NewPU(contextID, puInfo, e.externalIPCacheTimeout)
	if err != nil {
		return fmt.Errorf("error creating new pu: %s", err)
	}

	e.puContexts.AddOrUpdate(contextID, pu)

	sctx, err := e.registry.Register(contextID, puInfo, pu, e.secrets)
	if err != nil {
		return fmt.Errorf("policy conflicts detected: %s", err)
	}

	caPool := e.expandCAPool(sctx.RootCA)

	// now instantiate the apiAuth and metadata
	// create a new server if it doesn't exist yet
	if _, err := e.clients.Get(contextID); err != nil {
		zap.L().Debug("creating new auth and sds servers", zap.String("puID", contextID))
		ingressServer, err := envoyproxy.NewExtAuthzServer(contextID, e.puContexts, e.collector, envoyproxy.IngressDirection)
		if err != nil {
			zap.L().Error("Cannot create and run IngressServer", zap.Error(err))
			return err
		}

		egressServer, err := envoyproxy.NewExtAuthzServer(contextID, e.puContexts, e.collector, envoyproxy.EgressDirection)
		if err != nil {
			zap.L().Error("Cannot create and run EgressServer", zap.Error(err))
			ingressServer.Stop()
			return err
		}
		sdsServer, err := envoyproxy.NewSdsServer(puInfo)
		if err != nil {
			zap.L().Error("Cannot create and run SdsServer", zap.Error(err))
			return err
		}
		// Add the EnvoyServers to our cache
		if err := e.clients.Add(contextID, &envoyServers{ingress: ingressServer, egress: egressServer, sds: sdsServer}); err != nil {
			ingressServer.Stop()
			egressServer.Stop()
			sdsServer.Stop()
			return err
		}

	} else {
		// we have this client already, this is only a policy update
		zap.L().Debug("handling policy update for envoy servers", zap.String("puID", contextID))
		// For updates we need to update the certificates if we have new ones. Otherwise
		// we return. There is nothing else to do in case of policy update.
		// this required for the Envoy sds. So that the SDS picks the latest cert.
		if c, cerr := e.clients.Get(contextID); cerr == nil {
			_, perr := e.processCertificateUpdates(puInfo, c.(*envoyServers).sds, caPool)
			if perr != nil {
				zap.L().Error("unable to update certificates for services", zap.Error(perr))
				return perr
			}
			return nil
		}
	}

	return nil
}

// processCertificateUpdates processes the certificate information and updates
// the servers.
func (e *Enforcer) processCertificateUpdates(puInfo *policy.PUInfo, server *envoyproxy.SdsServer, caPool *x509.CertPool) (bool, error) {

	// If there are certificates provided, we will need to update them for the
	// services. If the certificates are nil, we ignore them.
	certPEM, keyPEM, caPEM := puInfo.Policy.ServiceCertificates()
	if certPEM == "" || keyPEM == "" {
		return false, nil
	}

	// Process any updates on the cert pool
	if caPEM != "" {
		if !caPool.AppendCertsFromPEM([]byte(caPEM)) {
			zap.L().Warn("Failed to add Services CA")
		}
	}

	// Create the TLS certificate
	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return false, fmt.Errorf("Invalid certificates: %s", err)
	}
	// update the sds server certs.
	server.UpdateSecrets(&tlsCert, caPool, e.secrets, certPEM, keyPEM)
	return true, nil
}

func (e *Enforcer) expandCAPool(externalCAs [][]byte) *x509.CertPool {
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		zap.L().Error("cannot process system pool", zap.Error(err))
		return e.systemCAPool
	}
	if ok := systemPool.AppendCertsFromPEM(e.secrets.PublicSecrets().CertAuthority()); !ok {
		zap.L().Error("cannot appen system CA", zap.Error(err))
		return e.systemCAPool
	}
	for _, ca := range externalCAs {
		if ok := systemPool.AppendCertsFromPEM(ca); !ok {
			zap.L().Error("cannot append external service ca", zap.String("CA", string(ca)))
		}
	}
	return systemPool
}

// Unenforce stops enforcing policy for the given IP.
func (e *Enforcer) Unenforce(contextID string) error {
	e.Lock()
	defer e.Unlock()
	return nil
}

// UpdateSecrets -- updates the secrets of running enforcers managed by trireme. Remote enforcers will get the secret updates with the next policy push
func (e *Enforcer) UpdateSecrets(secrets secrets.Secrets) error {
	e.Lock()
	defer e.Unlock()
	e.secrets = secrets
	return nil
}

// SetTargetNetworks is unimplemented in the envoy authorizer
func (e *Enforcer) SetTargetNetworks(cfg *runtime.Configuration) error {
	return nil
}

// SetLogLevel is unimplemented in the envoy authorizer
func (e *Enforcer) SetLogLevel(level constants.LogLevel) error {
	return nil
}

// CleanUp is unimplemented in the envoy authorizer
func (e *Enforcer) CleanUp() error {
	return nil
}

// Run is unimplemented in the envoy authorizer
func (e *Enforcer) Run(ctx context.Context) error {
	return nil
}

// GetFilterQueue is unimplemented in the envoy authorizer
func (e *Enforcer) GetFilterQueue() *fqconfig.FilterQueue {
	return nil
}

// EnableDatapathPacketTracing is unimplemented in the envoy authorizer
func (e *Enforcer) EnableDatapathPacketTracing(ctx context.Context, contextID string, direction packettracing.TracingDirection, interval time.Duration) error {
	return nil
}

// EnableIPTablesPacketTracing is unimplemented in the envoy authorizer
func (e *Enforcer) EnableIPTablesPacketTracing(ctx context.Context, contextID string, interval time.Duration) error {
	return nil
}
