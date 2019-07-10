package envoyproxy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.aporeto.io/trireme-lib/controller/pkg/servicetokens"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/envoyproxy/authz"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.uber.org/zap"

	"go.aporeto.io/trireme-lib/collector"
	enforcerconstants "go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
)

// EnvoyProxy struct
type EnvoyProxy struct {
	// the tokenaccessor is technically not used at the moment
	// and will only become valuable when we are going to find
	// a way on how to do authorization with the network ext_authz filter
	tokenaccessor          tokenaccessor.TokenAccessor
	collector              collector.EventCollector
	externalIPCacheTimeout time.Duration
	secrets                secrets.Secrets

	puContexts cache.DataStore
	clients    cache.DataStore
	verifier   *servicetokens.Verifier

	sync.RWMutex
}

type envoyAuthzServers struct {
	ingress *authz.Server
	egress  *authz.Server
}

// NewEnvoyProxy returns a new EnvoyProxy
func NewEnvoyProxy(tp tokenaccessor.TokenAccessor, c collector.EventCollector, externalIPCacheTimeout time.Duration, s secrets.Secrets) (*EnvoyProxy, error) {

	// same logic as in the nfqdatapath
	if externalIPCacheTimeout <= 0 {
		var err error
		externalIPCacheTimeout, err = time.ParseDuration(enforcerconstants.DefaultExternalIPTimeout)
		if err != nil {
			externalIPCacheTimeout = time.Second
		}
	}

	return &EnvoyProxy{
		tokenaccessor:          tp,
		collector:              c,
		externalIPCacheTimeout: externalIPCacheTimeout,
		secrets:                s,
		puContexts:             cache.NewCache("puContexts"),
		clients:                cache.NewCache("clients"),
		verifier:               servicetokens.NewVerifier(s, nil),
	}, nil
}

// Secrets implements the LockedSecrets
func (p *EnvoyProxy) Secrets() (secrets.Secrets, func()) {
	p.RLock()
	return p.secrets, p.RUnlock
}

// Run starts all the network side proxies. Application side proxies will
// have to start during enforce in order to support multiple Linux processes.
func (p *EnvoyProxy) Run(ctx context.Context) error {
	return nil
}

// Enforce implements enforcer.Enforcer interface. It will create the necessary
// proxies for the particular PU. Enforce can be called multiple times, once
// for every policy update.
func (p *EnvoyProxy) Enforce(puID string, puInfo *policy.PUInfo) error {
	return p.enforceWithContext(context.Background(), puID, puInfo)
}

func (p *EnvoyProxy) enforceWithContext(ctx context.Context, puID string, puInfo *policy.PUInfo) error {
	p.Lock()
	defer p.Unlock()

	// Handle the updates and events around the PU Context first
	// Always create a new PU context
	puContext, err := pucontext.NewPU(puID, puInfo, p.externalIPCacheTimeout)
	if err != nil {
		return fmt.Errorf("error creating new PU context: %s", err)
	}

	// pucontext launches a go routine to periodically
	// lookup dns names. ctx cancel signals the go routine to exit
	if existingPUContextRaw, _ := p.puContexts.Get(puID); existingPUContextRaw != nil {
		if existingPUContext, ok := existingPUContextRaw.(*pucontext.PUContext); ok {
			existingPUContext.CancelFunc()
		}
	}

	// now add or update the PU context
	p.puContexts.AddOrUpdate(puID, puContext)

	// create a new server if it doesn't exist yet
	if _, err := p.clients.Get(puID); err != nil {
		zap.L().Debug("creating new ext_authz servers", zap.String("puID", puID))
		ingressServer, err := authz.NewExtAuthzServer(puID, p.puContexts, p.collector, p.verifier, p, authz.IngressDirection)
		if err != nil {
			return err
		}

		egressServer, err := authz.NewExtAuthzServer(puID, p.puContexts, p.collector, p.verifier, p, authz.EgressDirection)
		if err != nil {
			ingressServer.Stop()
			return err
		}

		// try to add this to our cache
		if err := p.clients.Add(puID, &envoyAuthzServers{ingress: ingressServer, egress: egressServer}); err != nil {
			ingressServer.Stop()
			egressServer.Stop()
			return err
		}
	} else {
		// we have this client already, this is only a policy update
		zap.L().Debug("handling policy update for ext_authz server", zap.String("puID", puID))
	}

	return nil
}

// Unenforce implements enforcer.Enforcer interface. It will shutdown the app side
// of the proxy.
func (p *EnvoyProxy) Unenforce(puID string) error {
	return p.unenforceWithContext(context.Background(), puID)
}

func (p *EnvoyProxy) unenforceWithContext(ctx context.Context, puID string) error {
	p.Lock()
	defer p.Unlock()

	// stop the authz servers
	rawAuthzServers, err := p.clients.Get(puID)
	if err != nil {
		return err
	}

	server := rawAuthzServers.(*envoyAuthzServers)
	shutdownCtx, shutdownCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer shutdownCtxCancel()

	var wg sync.WaitGroup
	shutdownCh := make(chan struct{})
	wg.Add(2)
	go func() {
		server.ingress.GracefulStop()
		wg.Done()
	}()
	go func() {
		server.egress.GracefulStop()
		wg.Done()
	}()
	go func() {
		wg.Wait()
		shutdownCh <- struct{}{}
	}()

	select {
	case <-shutdownCtx.Done():
		zap.L().Warn("Graceful shutdown of ext_authz server did not finish in time. Shutting down hard now...", zap.String("puID", puID), zap.Error(shutdownCtx.Err()))
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			server.ingress.Stop()
			wg.Done()
		}()
		go func() {
			server.egress.Stop()
			wg.Done()
		}()
		wg.Wait()
	case <-shutdownCh:
	}

	// pucontext launches a go routine to periodically
	// lookup dns names. ctx cancel signals the go routine to exit
	if existingPUContextRaw, _ := p.puContexts.Get(puID); existingPUContextRaw != nil {
		if existingPUContext, ok := existingPUContextRaw.(*pucontext.PUContext); ok {
			existingPUContext.CancelFunc()
		}
	}

	if err := p.puContexts.RemoveWithDelay(puID, 10*time.Second); err != nil {
		zap.L().Debug("Unable to remove PU context from cache", zap.String("puID", puID), zap.Error(err))
	}

	return nil
}

// GetFilterQueue is a stub for TCP proxy
func (p *EnvoyProxy) GetFilterQueue() *fqconfig.FilterQueue {
	return nil
}

// UpdateSecrets updates the secrets of running enforcers managed by trireme. Remote enforcers will
// get the secret updates with the next policy push.
func (p *EnvoyProxy) UpdateSecrets(secret secrets.Secrets) error {
	p.Lock()
	defer p.Unlock()
	p.secrets = secret
	p.verifier.UpdateSecrets(secret, nil)
	return nil
}

// CleanUp implements the cleanup interface. Not much to do here.
func (p *EnvoyProxy) CleanUp() error {
	return nil
}

// SetTargetNetworks implements the enforcer interface. Not much to do here at the moment.
func (p *EnvoyProxy) SetTargetNetworks(cfg *runtime.Configuration) error {
	return nil
}

// EnableDatapathPacketTracing implements the DebugInfo interface. Not much to do here at the moment.
func (p *EnvoyProxy) EnableDatapathPacketTracing(contextID string, direction packettracing.TracingDirection, interval time.Duration) error {
	return nil
}

// EnableIPTablesPacketTracing implements the DebugInfo interface. Not much to do here at the moment.
func (p *EnvoyProxy) EnableIPTablesPacketTracing(ctx context.Context, contextID string, interval time.Duration) error {
	return nil
}
