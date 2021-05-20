package applicationproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/blang/semver"
	"github.com/opentracing/opentracing-go"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	tcommon "go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/common"
	httpproxy "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/http"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/protomux"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/tcp"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/ephemeralkeys"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

// ServerInterface describes the methods required by an application processor.
type ServerInterface interface {
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

	tokenaccessor   tokenaccessor.TokenAccessor
	collector       collector.EventCollector
	puFromID        cache.DataStore
	secrets         secrets.Secrets
	datapathKeyPair ephemeralkeys.KeyAccessor
	agentVersion    semver.Version

	clients     cache.DataStore
	tokenIssuer tcommon.ServiceTokenIssuer
	sync.RWMutex
}

// NewAppProxy creates a new instance of the application proxy.
func NewAppProxy(
	tp tokenaccessor.TokenAccessor,
	c collector.EventCollector,
	puFromID cache.DataStore,
	s secrets.Secrets,
	t tcommon.ServiceTokenIssuer,
	datapathKeyPair ephemeralkeys.KeyAccessor,
	agentVersion semver.Version,
) (*AppProxy, error) {

	return &AppProxy{
		collector:       c,
		tokenaccessor:   tp,
		secrets:         s,
		puFromID:        puFromID,
		cert:            nil,
		clients:         cache.NewCache("clients"),
		tokenIssuer:     t,
		datapathKeyPair: datapathKeyPair,
		agentVersion:    agentVersion,
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

	span, tctx := opentracing.StartSpanFromContext(ctx, "applicationproxy.enforce")
	defer span.Finish()

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

	sctx, err := serviceregistry.Instance().Register(puID, puInfo, puContext, p.secrets)
	if err != nil {
		return fmt.Errorf("policy conflicts detected: %s", err)
	}

	caPool, err := p.expandCAPool(sctx.RootCA)
	if err != nil {
		return err
	}

	// For updates we need to update the certificates if we have new ones. Otherwise
	// we return. There is nothing else to do in case of policy update.
	if c, cerr := p.clients.Get(puID); cerr == nil {
		if _, perr := p.processCertificateUpdates(puInfo, c.(*clientData), caPool); perr != nil {
			zap.L().Error("unable to update certificates and services", zap.Error(perr))
			return perr
		}
		return nil
	}

	// Create the network listener and cache it so that we can terminate it later.
	l, err := p.createNetworkListener(tctx, ":"+puInfo.Policy.ServicesListeningPort())
	if err != nil {
		zap.L().Error("Failed to create network listener", zap.Error(err))
		return fmt.Errorf("Cannot create listener on port %s: %s", puInfo.Policy.ServicesListeningPort(), err)
	}

	// Create a new client entry and start the servers.
	client := &clientData{
		netserver: map[common.ListenerType]ServerInterface{},
	}
	client.protomux = protomux.NewMultiplexedListener(l, constants.ProxyMarkInt, puID)

	// Listen to HTTP requests from the clients
	client.netserver[common.HTTPApplication], err = p.registerAndRun(tctx, puID, common.HTTPApplication, client.protomux, caPool, true)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", common.HTTPApplication, err)
	}

	// Listen to HTTPS requests on the network side.
	client.netserver[common.HTTPSNetwork], err = p.registerAndRun(tctx, puID, common.HTTPSNetwork, client.protomux, caPool, false)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", common.HTTPSNetwork, err)
	}

	// Listen to HTTP requests on the network side - mainly used for health probes - completely insecure for
	// anything else.
	client.netserver[common.HTTPNetwork], err = p.registerAndRun(tctx, puID, common.HTTPNetwork, client.protomux, caPool, false)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", common.HTTPNetwork, err)
	}

	// TCP Requests for clients
	client.netserver[common.TCPApplication], err = p.registerAndRun(tctx, puID, common.TCPApplication, client.protomux, caPool, true)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", common.TCPApplication, err)
	}

	// TCP Requests from the network side
	client.netserver[common.TCPNetwork], err = p.registerAndRun(tctx, puID, common.TCPNetwork, client.protomux, caPool, false)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", common.TCPNetwork, err)
	}

	if _, err = p.processCertificateUpdates(puInfo, client, caPool); err != nil {
		zap.L().Error("Failed to update certificates", zap.Error(err))
		return fmt.Errorf("Certificates not updated: %s", err)
	}

	// Add the client to the cache
	p.clients.AddOrUpdate(puID, client)

	// Start the connection multiplexer
	go client.protomux.Serve(tctx) // nolint

	return nil
}

// Unenforce implements enforcer.Enforcer interface. It will shutdown the app side
// of the proxy.
func (p *AppProxy) Unenforce(ctx context.Context, puID string) error {
	p.Lock()
	defer p.Unlock()

	// Remove pu from registry
	if err := serviceregistry.Instance().Unregister(puID); err != nil {
		return err
	}

	// Find the correct client.
	c, err := p.clients.Get(puID)
	if err != nil {
		return fmt.Errorf("Unable to find client")
	}
	client := c.(*clientData)

	// Terminate the connection multiplexer.
	// Do it before shutting down servers below to avoid Accept() errors.
	client.protomux.Close()

	// Shutdown all the servers and unregister listeners.
	for t, server := range client.netserver {
		if err := client.protomux.UnregisterListener(t); err != nil {
			zap.L().Error("Unable to unregister client", zap.Int("type", int(t)), zap.Error(err))
		}
		if err := server.ShutDown(); err != nil {
			zap.L().Debug("Unable to shutdown client server", zap.Error(err))
		}
	}

	// Remove the client from the cache.
	return p.clients.Remove(puID)
}

// GetFilterQueue is a stub for TCP proxy
func (p *AppProxy) GetFilterQueue() *fqconfig.FilterQueue {
	return nil
}

// Ping runs ping to the given config based on the service type. Returns error on invalid types.
func (p *AppProxy) Ping(ctx context.Context, contextID string, sctx *serviceregistry.ServiceContext, sdata *serviceregistry.DependentServiceData, pingConfig *policy.PingConfig) error {

	if pingConfig == nil || sctx == nil || sdata == nil {
		zap.L().Debug("unable to run ping",
			zap.Reflect("pingconfig", pingConfig),
			zap.Reflect("serviceCtx", sctx),
			zap.Reflect("serviceData", sdata),
		)

		return nil
	}

	c, err := p.clients.Get(contextID)
	if err != nil {
		return fmt.Errorf("unable to find client with contextID: %s", contextID)
	}
	client := c.(*clientData)

	switch sdata.ServiceObject.Type {
	case policy.ServiceTCP:
		return client.netserver[common.TCPApplication].(*tcp.Proxy).InitiatePing(ctx, sctx, sdata, pingConfig)
	case policy.ServiceHTTP:
		return client.netserver[common.HTTPApplication].(*httpproxy.Config).InitiatePing(ctx, sctx, sdata, pingConfig)
	default:
		return fmt.Errorf("unknown service type: %d", sdata.ServiceObject.Type)
	}
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

	// Create a new sub-ordinate listerner and register it for the requested type.
	listener, err := mux.RegisterListener(ltype)
	if err != nil {
		return nil, fmt.Errorf("Cannot register listener: %s", err)
	}

	// Start the corresponding proxy
	switch ltype {
	case common.HTTPApplication, common.HTTPSApplication, common.HTTPNetwork, common.HTTPSNetwork:

		// If the protocol is encrypted, wrap it with TLS.
		encrypted := false
		if ltype == common.HTTPSNetwork {
			encrypted = true
		}

		c := httpproxy.NewHTTPProxy(p.collector, puID, caPool, appproxy, constants.ProxyMarkInt, p.secrets, p.tokenIssuer, p.datapathKeyPair, p.agentVersion)
		return c, c.RunNetworkServer(ctx, listener, encrypted)

	default:
		c := tcp.NewTCPProxy(p.collector, puID, p.cert, caPool, p.agentVersion, constants.ProxyMarkInt)
		return c, c.RunNetworkServer(ctx, listener)
	}
}

// createNetworkListener starts a network listener (traffic from network to PUs)
func (p *AppProxy) createNetworkListener(ctx context.Context, port string) (net.Listener, error) {
	return markedconn.NewSocketListener(ctx, port, constants.ProxyMarkInt)
}

// processCertificateUpdates processes the certificate information and updates
// the servers.
func (p *AppProxy) processCertificateUpdates(puInfo *policy.PUInfo, client *clientData, caPool *x509.CertPool) (bool, error) { // nolint:unparam

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

func (p *AppProxy) expandCAPool(externalCAs [][]byte) (*x509.CertPool, error) {

	caPool := x509.NewCertPool()

	if ok := caPool.AppendCertsFromPEM(p.secrets.CertAuthority()); !ok {
		return nil, fmt.Errorf("cannot append secrets CA %s", string(p.secrets.CertAuthority()))
	}

	for _, ca := range externalCAs {
		if ok := caPool.AppendCertsFromPEM(ca); !ok {
			return nil, fmt.Errorf("cannot append external service ca %s ", string(ca))
		}
	}

	return caPool, nil
}

// ServiceData returns the servicectx and dependentservice for the given ip:port.
func (p *AppProxy) ServiceData(
	contextID string,
	ip net.IP,
	port int,
	serviceAddresses map[string][]string) (*serviceregistry.ServiceContext, *serviceregistry.DependentServiceData, error) {

	if sctx, sdata, err := serviceregistry.Instance().RetrieveDependentServiceDataByIDAndNetwork(contextID, ip, port, ""); err == nil {
		return sctx, sdata, nil
	}

	if len(serviceAddresses) == 0 {
		return nil, nil, errors.New("no service context found")
	}

	sctx, err := serviceregistry.Instance().RetrieveServiceByID(contextID)
	if err != nil {
		return nil, nil, err
	}

	update := false
	for _, svc := range sctx.PU.Policy.DependentServices() {

		addrs, ok := serviceAddresses[svc.ID]
		if !ok {
			continue
		}

		min, max := svc.NetworkInfo.Ports.Range()

		for _, addr := range addrs {

			if ip := net.ParseIP(addr); ip.To4() == nil {
				continue
			}

			if _, exists := svc.NetworkInfo.Addresses[addr+"/32"]; exists {
				continue
			}

			_, ipNet, _ := net.ParseCIDR(addr + "/32")
			for i := int(min); i <= int(max); i++ {
				if err := ipsetmanager.V4().AddIPPortToDependentService(contextID, ipNet, strconv.Itoa(i)); err != nil {
					zap.L().Debug("Error adding dependent service ip port to ipset", zap.Error(err))
				}
			}

			update = true
			svc.NetworkInfo.Addresses[ipNet.String()] = struct{}{}
		}
	}

	if update {
		if err := serviceregistry.Instance().UpdateDependentServicesByID(contextID); err != nil {
			zap.L().Error("Error updating dependent services", zap.Error(err))
		}
	}

	return serviceregistry.Instance().RetrieveDependentServiceDataByIDAndNetwork(contextID, ip, port, "")
}
