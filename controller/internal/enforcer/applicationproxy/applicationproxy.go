package applicationproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"

	"go.aporeto.io/trireme-lib/v11/collector"
	tcommon "go.aporeto.io/trireme-lib/v11/common"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/applicationproxy/common"
	httpproxy "go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/applicationproxy/http"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/applicationproxy/protomux"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/applicationproxy/tcp"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/v11/policy"
	"go.aporeto.io/trireme-lib/v11/utils/cache"
	"go.uber.org/zap"
)

const (
	proxyMarkInt = 0x40 //Duplicated from supervisor/iptablesctrl refer to it
)

// ServerInterface describes the methods required by an application processor.
type ServerInterface interface {
	RunNetworkServer(ctx context.Context, l net.Listener, encrypted bool) error
	UpdateSecrets(cert *tls.Certificate, ca *x509.CertPool, secrets secrets.Secrets, certPEM, keyPEM string)
	ShutDown() error
}

type clientData struct {
	protomux  *protomux.MultiplexedListener
	netserver map[common.ListenerType]ServerInterface
}

// AppProxy maintains state for proxies connections from listen to backend.
type AppProxy struct {
	cert *tls.Certificate

	tokenaccessor tokenaccessor.TokenAccessor
	collector     collector.EventCollector
	puFromID      cache.DataStore
	systemCAPool  *x509.CertPool
	secrets       secrets.Secrets

	registry *serviceregistry.Registry

	clients     cache.DataStore
	tokenIssuer tcommon.ServiceTokenIssuer
	sync.RWMutex
}

// NewAppProxy creates a new instance of the application proxy.
func NewAppProxy(
	tp tokenaccessor.TokenAccessor,
	c collector.EventCollector,
	puFromID cache.DataStore,
	certificate *tls.Certificate,
	s secrets.Secrets,
	t tcommon.ServiceTokenIssuer,
) (*AppProxy, error) {

	systemPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	if ok := systemPool.AppendCertsFromPEM(s.PublicSecrets().CertAuthority()); !ok {
		return nil, fmt.Errorf("error while adding provided CA")
	}

	return &AppProxy{
		collector:     c,
		tokenaccessor: tp,
		secrets:       s,
		puFromID:      puFromID,
		cert:          certificate,
		clients:       cache.NewCache("clients"),
		systemCAPool:  systemPool,
		registry:      serviceregistry.NewServiceRegistry(),
		tokenIssuer:   t,
	}, nil
}

// Run starts all the network side proxies. Application side proxies will
// have to start during enforce in order to support multiple Linux processes.
func (p *AppProxy) Run(ctx context.Context) error {

	return nil
}

// Enforce implements enforcer.Enforcer interface. It will create the necessary
// proxies for the particular PU. Enforce can be called multiple times, once
// for every policy update.
func (p *AppProxy) Enforce(ctx context.Context, puID string, puInfo *policy.PUInfo) error {

	p.Lock()
	defer p.Unlock()

	if puInfo.Policy.ServicesListeningPort() == "0" {
		zap.L().Warn("Services listening port not specified - not activating proxy")
		return nil
	}

	data, err := p.puFromID.Get(puID)
	if err != nil || data == nil {
		return fmt.Errorf("undefined PU - Context not found: %s", puID)
	}

	puContext, ok := data.(*pucontext.PUContext)
	if !ok {
		return fmt.Errorf("bad data types for puContext")
	}

	sctx, err := p.registry.Register(puID, puInfo, puContext, p.secrets)
	if err != nil {
		return fmt.Errorf("policy conflicts detected: %s", err)
	}

	caPool := p.expandCAPool(sctx.RootCA)

	// For updates we need to update the certificates if we have new ones. Otherwise
	// we return. There is nothing else to do in case of policy update.
	if c, cerr := p.clients.Get(puID); cerr == nil {
		_, perr := p.processCertificateUpdates(puInfo, c.(*clientData), caPool)
		if perr != nil {
			zap.L().Error("unable to update certificates and services", zap.Error(perr))
			return perr
		}
		return nil
	}

	// Create the network listener and cache it so that we can terminate it later.
	l, err := p.createNetworkListener(ctx, ":"+puInfo.Policy.ServicesListeningPort())
	if err != nil {
		return fmt.Errorf("Cannot create listener: port:%s %s", puInfo.Policy.ServicesListeningPort(), err)
	}

	// Create a new client entry and start the servers.
	client := &clientData{
		netserver: map[common.ListenerType]ServerInterface{},
	}
	client.protomux = protomux.NewMultiplexedListener(l, proxyMarkInt, p.registry, puID)

	// Listen to HTTP requests from the clients
	client.netserver[common.HTTPApplication], err = p.registerAndRun(ctx, puID, common.HTTPApplication, client.protomux, caPool, true)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", common.HTTPApplication, err)
	}

	// Listen to HTTPS requests on the network side.
	client.netserver[common.HTTPSNetwork], err = p.registerAndRun(ctx, puID, common.HTTPSNetwork, client.protomux, caPool, false)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", common.HTTPSNetwork, err)
	}

	// Listen to HTTP requests on the network side - mainly used for health probes - completely insecure for
	// anything else.
	client.netserver[common.HTTPNetwork], err = p.registerAndRun(ctx, puID, common.HTTPNetwork, client.protomux, caPool, false)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", common.HTTPNetwork, err)
	}

	// TCP Requests for clients
	client.netserver[common.TCPApplication], err = p.registerAndRun(ctx, puID, common.TCPApplication, client.protomux, caPool, true)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", common.TCPApplication, err)
	}

	// TCP Requests from the network side
	client.netserver[common.TCPNetwork], err = p.registerAndRun(ctx, puID, common.TCPNetwork, client.protomux, caPool, false)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", common.TCPNetwork, err)
	}

	if _, err := p.processCertificateUpdates(puInfo, client, caPool); err != nil {
		zap.L().Error("Failed to update certificates", zap.Error(err))
		return fmt.Errorf("Certificates not updated:  %s ", err)
	}

	// Add the client to the cache
	p.clients.AddOrUpdate(puID, client)

	// Start the connection multiplexer
	go client.protomux.Serve(ctx) // nolint

	return nil
}

// Unenforce implements enforcer.Enforcer interface. It will shutdown the app side
// of the proxy.
func (p *AppProxy) Unenforce(ctx context.Context, puID string) error {
	p.Lock()
	defer p.Unlock()

	// Remove pu from registry
	if err := p.registry.Unregister(puID); err != nil {
		return err
	}

	// Find the correct client.
	c, err := p.clients.Get(puID)
	if err != nil {
		return fmt.Errorf("Unable to find client")
	}
	client := c.(*clientData)

	// Shutdown all the servers and unregister listeners.
	for t, server := range client.netserver {
		if err := client.protomux.UnregisterListener(t); err != nil {
			zap.L().Error("Unable to unregister client", zap.Int("type", int(t)), zap.Error(err))
		}
		if err := server.ShutDown(); err != nil {
			zap.L().Debug("Unable to shutdown client server", zap.Error(err))
		}
	}

	// Terminate the connection multiplexer.
	client.protomux.Close()

	// Remove the client from the cache.
	return p.clients.Remove(puID)
}

// GetFilterQueue is a stub for TCP proxy
func (p *AppProxy) GetFilterQueue() *fqconfig.FilterQueue {
	return nil
}

// UpdateSecrets updates the secrets of running enforcers managed by trireme. Remote enforcers will
// get the secret updates with the next policy push.
func (p *AppProxy) UpdateSecrets(secret secrets.Secrets) error {
	p.Lock()
	defer p.Unlock()
	p.secrets = secret
	return nil
}

// registerAndRun registers a new listener of the given type and runs the corresponding server
func (p *AppProxy) registerAndRun(ctx context.Context, puID string, ltype common.ListenerType, mux *protomux.MultiplexedListener, caPool *x509.CertPool, appproxy bool) (ServerInterface, error) {
	var listener net.Listener
	var err error

	// Create a new sub-ordinate listerner and register it for the requested type.
	listener, err = mux.RegisterListener(ltype)
	if err != nil {
		return nil, fmt.Errorf("Cannot register  listener: %s", err)
	}

	// If the protocol is encrypted, wrapp it with TLS.
	encrypted := false
	if ltype == common.HTTPSNetwork {
		encrypted = true
	}

	// Start the corresponding proxy
	switch ltype {
	case common.HTTPApplication, common.HTTPSApplication, common.HTTPNetwork, common.HTTPSNetwork:
		c := httpproxy.NewHTTPProxy(p.collector, puID, caPool, appproxy, proxyMarkInt, p.secrets, p.registry, p.tokenIssuer)
		return c, c.RunNetworkServer(ctx, listener, encrypted)
	default:
		c := tcp.NewTCPProxy(p.tokenaccessor, p.collector, puID, p.registry, p.cert, caPool)
		return c, c.RunNetworkServer(ctx, listener, encrypted)
	}
}

// createNetworkListener starts a network listener (traffic from network to PUs)
func (p *AppProxy) createNetworkListener(ctx context.Context, port string) (net.Listener, error) {
	return markedconn.NewSocketListener(ctx, port, proxyMarkInt)
}

// processCertificateUpdates processes the certificate information and updates
// the servers.
// nolint: unparam (the bool return is not used within the library, but maybe used by clients of the library)
func (p *AppProxy) processCertificateUpdates(puInfo *policy.PUInfo, client *clientData, caPool *x509.CertPool) (bool, error) {

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

	for _, server := range client.netserver {
		server.UpdateSecrets(&tlsCert, caPool, p.secrets, certPEM, keyPEM)
	}
	return true, nil
}

func (p *AppProxy) expandCAPool(externalCAs [][]byte) *x509.CertPool {
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		zap.L().Error("cannot process system pool", zap.Error(err))
		return p.systemCAPool
	}
	if ok := systemPool.AppendCertsFromPEM(p.secrets.PublicSecrets().CertAuthority()); !ok {
		zap.L().Error("cannot appen system CA", zap.Error(err))
		return p.systemCAPool
	}
	for _, ca := range externalCAs {
		if ok := systemPool.AppendCertsFromPEM(ca); !ok {
			zap.L().Error("cannot append external service ca", zap.String("CA", string(ca)))
		}
	}
	return systemPool
}
