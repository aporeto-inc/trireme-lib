package envoyauthorizer

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
	enforcerconstants "go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
)

// Enforcer implements the Enforcer interface as an envoy authorizer
// and starts envoy external authz filter gRPC servers for enforcement.
type Enforcer struct {
	mode                   constants.ModeType
	collector              collector.EventCollector
	externalIPCacheTimeout time.Duration
	secrets                secrets.Secrets
	tokenIssuer            common.ServiceTokenIssuer

	registry   *serviceregistry.Registry
	puContexts cache.DataStore
	clients    cache.DataStore

	sync.RWMutex
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

	return &Enforcer{
		mode:                   mode,
		collector:              eventCollector,
		externalIPCacheTimeout: externalIPCacheTimeout,
		secrets:                secrets,
		tokenIssuer:            tokenIssuer,
		registry:               serviceregistry.NewServiceRegistry(),
		puContexts:             cache.NewCache("puContexts"),
		clients:                cache.NewCache("clients"),
	}, nil
}

// Secrets implements the LockedSecrets
func (e *Enforcer) Secrets() (secrets.Secrets, func()) {
	e.RLock()
	return e.secrets, e.RUnlock
}

// Enforce starts enforcing policies for the given policy.PUInfo.
func (e *Enforcer) Enforce(contextID string, puInfo *policy.PUInfo) error {
	e.Lock()
	defer e.Unlock()
	return nil
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
