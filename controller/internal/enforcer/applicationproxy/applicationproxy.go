package applicationproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/http"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/protomux"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/tcp"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"go.aporeto.io/trireme-lib/controller/pkg/auth"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/urisearch"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

const (
	proxyMarkInt = 0x40 //Duplicated from supervisor/iptablesctrl refer to it

)

// ServerInterface describes the methods required by an application processor.
type ServerInterface interface {
	RunNetworkServer(ctx context.Context, l net.Listener, encrypted bool) error
	UpdateSecrets(cert *tls.Certificate, ca *x509.CertPool, secrets secrets.Secrets, certPEM, keyPEM string)
	UpdateCaches(portCache map[int]*policy.ApplicationService, portMapping map[int]int)
	ShutDown() error
}

type clientData struct {
	protomux  *protomux.MultiplexedListener
	netserver map[protomux.ListenerType]ServerInterface
}

// AppProxy maintains state for proxies connections from listen to backend.
type AppProxy struct {
	cert *tls.Certificate

	tokenaccessor      tokenaccessor.TokenAccessor
	collector          collector.EventCollector
	authProcessorCache cache.DataStore
	puFromID           cache.DataStore
	dependentAPICache  cache.DataStore
	systemCAPool       *x509.CertPool
	secrets            secrets.Secrets

	clients cache.DataStore
	sync.RWMutex
}

// NewAppProxy creates a new instance of the application proxy.
func NewAppProxy(tp tokenaccessor.TokenAccessor, c collector.EventCollector, puFromID cache.DataStore, certificate *tls.Certificate, s secrets.Secrets) (*AppProxy, error) {

	systemPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	// We append the CA only if we are not in PSK mode as it doesn't provide a CA.
	if s.PublicSecrets().SecretsType() != secrets.PSKType {
		if ok := systemPool.AppendCertsFromPEM(s.PublicSecrets().CertAuthority()); !ok {
			return nil, fmt.Errorf("error while adding provided CA")
		}
	}

	return &AppProxy{
		collector:          c,
		tokenaccessor:      tp,
		secrets:            s,
		puFromID:           puFromID,
		cert:               certificate,
		authProcessorCache: cache.NewCache("authprocessors"),
		clients:            cache.NewCache("clients"),
		dependentAPICache:  cache.NewCache("dependencies"),
		systemCAPool:       systemPool,
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

	// First update the caches with the new policy information.
	var authProcessor *auth.Processor
	if cachedProcessor, err := p.authProcessorCache.Get(puID); err == nil {
		authProcessor = cachedProcessor.(*auth.Processor)
		authProcessor.UpdateSecrets(p.secrets, nil)
	} else {
		authProcessor = auth.NewProcessor(p.secrets, nil)
		p.authProcessorCache.AddOrUpdate(puID, authProcessor)
	}

	portCache, portMapping := buildExposedServices(authProcessor, puInfo.Policy.ExposedServices())
	dependentCache, caPoolPEM := buildDependentCaches(puInfo.Policy.DependentServices())
	p.dependentAPICache.AddOrUpdate(puID, dependentCache)
	caPool := p.expandCAPool(caPoolPEM)

	// For updates we need to update the certificates if we have new ones. Otherwise
	// we return. There is nothing else to do in case of policy update.
	if c, cerr := p.clients.Get(puID); cerr == nil {
		_, perr := p.processCertificateUpdates(puInfo, c.(*clientData), caPool)
		if perr != nil {
			zap.L().Error("Failed to update certificates and services", zap.Error(perr))
			return perr
		}
		client, ok := c.(*clientData)
		if !ok {
			zap.L().Error("Internal server error - wrong data")
			return fmt.Errorf("bad data")
		}
		for _, server := range client.netserver {
			server.UpdateCaches(portCache, portMapping)
		}
		return p.registerServices(client, puInfo)
	}

	// Create the network listener and cache it so that we can terminate it later.
	l, err := p.createNetworkListener(":" + puInfo.Runtime.Options().ProxyPort)
	if err != nil {
		return fmt.Errorf("Cannot create listener: port:%s %s", puInfo.Runtime.Options().ProxyPort, err)
	}

	// Create a new client entry and start the servers.
	client := &clientData{
		netserver: map[protomux.ListenerType]ServerInterface{},
	}
	client.protomux = protomux.NewMultiplexedListener(l, proxyMarkInt)

	// Listen to HTTP requests from the clients
	client.netserver[protomux.HTTPApplication], err = p.registerAndRun(ctx, puID, protomux.HTTPApplication, client.protomux, caPool, portCache, portMapping, true)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", protomux.HTTPApplication, err)
	}

	// Listen to HTTPS requests on the network side.
	client.netserver[protomux.HTTPSNetwork], err = p.registerAndRun(ctx, puID, protomux.HTTPSNetwork, client.protomux, caPool, portCache, portMapping, false)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", protomux.HTTPSNetwork, err)
	}

	// Listen to HTTP requests on the network side - mainly used for health probes - completely insecure for
	// anything else.
	client.netserver[protomux.HTTPNetwork], err = p.registerAndRun(ctx, puID, protomux.HTTPNetwork, client.protomux, caPool, portCache, portMapping, false)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", protomux.HTTPNetwork, err)
	}

	// TCP Requests for clients
	client.netserver[protomux.TCPApplication], err = p.registerAndRun(ctx, puID, protomux.TCPApplication, client.protomux, caPool, portCache, portMapping, true)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", protomux.TCPApplication, err)
	}

	// TCP Requests from the network side
	client.netserver[protomux.TCPNetwork], err = p.registerAndRun(ctx, puID, protomux.TCPNetwork, client.protomux, caPool, portCache, portMapping, false)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", protomux.TCPNetwork, err)
	}

	if err := p.registerServices(client, puInfo); err != nil {
		return fmt.Errorf("Unable to register services: %s ", err)
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

	if err := p.authProcessorCache.Remove(puID); err != nil {
		zap.L().Warn("Cannot find PU in the API cache")
	}

	if err := p.dependentAPICache.Remove(puID); err != nil {
		zap.L().Warn("Cannot find PU in the Dependent API cache")
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

// registerServices register the services with the multiplexer
func (p *AppProxy) registerServices(client *clientData, puInfo *policy.PUInfo) error {

	register := client.protomux.NewServiceRegistry()

	// Register the ExposedServices with the multiplexer.
	for _, service := range puInfo.Policy.ExposedServices() {
		if err := register.Add(service.PrivateNetworkInfo, serviceTypeToNetworkListenerType(service.Type, false), true); err != nil {
			return fmt.Errorf("Duplicate exposed service definitions: %s", err)
		}
		if service.PublicNetworkInfo != nil {
			// We also need to listen on the public ports in this case.
			if err := register.Add(service.PublicNetworkInfo, serviceTypeToNetworkListenerType(service.Type, service.PublicServiceNoTLS), true); err != nil {
				return fmt.Errorf("Public network information overlaps with exposed services or other definitions: %s", err)
			}
		}
	}

	// Register the DependentServices with the multiplexer.
	for _, service := range puInfo.Policy.DependentServices() {
		if service.Type != policy.ServiceHTTP && service.Type != policy.ServiceTCP {
			continue
		}
		if err := register.Add(service.NetworkInfo, serviceTypeToApplicationListenerType(service.Type), false); err != nil {
			return fmt.Errorf("Duplicate dependent service: %s", err)
		}
	}

	client.protomux.SetServiceRegistry(register)
	return nil
}

// registerAndRun registers a new listener of the given type and runs the corresponding server
func (p *AppProxy) registerAndRun(ctx context.Context, puID string, ltype protomux.ListenerType, mux *protomux.MultiplexedListener, caPool *x509.CertPool, portCache map[int]*policy.ApplicationService, portMapping map[int]int, appproxy bool) (ServerInterface, error) {
	var listener net.Listener
	var err error

	// Create a new sub-ordinate listerner and register it for the requested type.
	listener, err = mux.RegisterListener(ltype)
	if err != nil {
		return nil, fmt.Errorf("Cannot register  listener: %s", err)
	}

	// If the protocol is encrypted, wrapp it with TLS.
	encrypted := false
	if ltype == protomux.HTTPSNetwork {
		encrypted = true
	}

	// Start the corresponding proxy
	switch ltype {
	case protomux.HTTPApplication, protomux.HTTPSApplication, protomux.HTTPNetwork, protomux.HTTPSNetwork:
		c := httpproxy.NewHTTPProxy(p.collector, puID, p.puFromID, caPool, p.authProcessorCache, p.dependentAPICache, appproxy, proxyMarkInt, p.secrets, portCache, portMapping)
		return c, c.RunNetworkServer(ctx, listener, encrypted)
	default:
		c := tcp.NewTCPProxy(p.tokenaccessor, p.collector, p.puFromID, puID, p.cert, caPool, portCache)
		return c, c.RunNetworkServer(ctx, listener, encrypted)
	}
}

// createNetworkListener starts a network listener (traffic from network to PUs)
func (p *AppProxy) createNetworkListener(port string) (net.Listener, error) {

	return markedconn.SocketListener(port, proxyMarkInt)
}

// processCertificateUpdates processes the certificate information and updates
// the servers.
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

func serviceTypeToNetworkListenerType(serviceType policy.ServiceType, noTLS bool) protomux.ListenerType {
	switch serviceType {
	case policy.ServiceHTTP:
		if noTLS {
			return protomux.HTTPNetwork
		}
		return protomux.HTTPSNetwork
	default:
		return protomux.TCPNetwork
	}
}

func serviceTypeToApplicationListenerType(serviceType policy.ServiceType) protomux.ListenerType {
	switch serviceType {
	case policy.ServiceHTTP:
		return protomux.HTTPApplication
	default:
		return protomux.TCPApplication
	}
}

// buildExposedServices builds the caches for the exposed services. It assumes that an authorization
// processor has already been created. It return two maps. The first has a mapping between
// destination rhost values and service IDs. The second has map between destination ports
// and service IDs.
// TODO:
// We just need the port mapping and not the rhost mapping since we know the original port. This will
// be simplified farther.
func buildExposedServices(p *auth.Processor, exposedServices policy.ApplicationServicesList) (map[int]*policy.ApplicationService, map[int]int) {
	portCache := map[int]*policy.ApplicationService{}
	portMapping := map[int]int{}
	usedServices := map[string]bool{}

	for _, service := range exposedServices {
		if service.Type != policy.ServiceHTTP && service.Type != policy.ServiceTCP {
			continue
		}
		port, err := service.PrivateNetworkInfo.Ports.SinglePort()
		if err == nil {
			portCache[int(port)] = service
			portMapping[int(port)] = int(port)
		}
		if service.PublicNetworkInfo != nil {
			// We also need to listen on the public ports in this case.
			if publicPort, err := service.PublicNetworkInfo.Ports.SinglePort(); err == nil {
				portCache[int(publicPort)] = service
				portMapping[int(publicPort)] = int(port)
			}
		}
		if service.Type != policy.ServiceHTTP {
			continue
		}
		if service.NetworkInfo.Ports.IsMultiPort() {
			zap.L().Error("Multiport HTTP services are not supported")
			continue
		}
		ruleCache := urisearch.NewAPICache(service.HTTPRules, service.ID, false)
		usedServices[service.ID] = true
		p.AddOrUpdateService(service.ID, ruleCache, service.UserAuthorizationType, service.UserAuthorizationHandler, service.UserTokenToHTTPMappings)
	}
	p.RemoveUnusedServices(usedServices)
	return portCache, portMapping
}

// buildDependentCaches builds the caches for the dependent services.
// It returns a map of API caches based on destination rhost values and
// and array of public CAs for accessing external services.
func buildDependentCaches(dependentServices policy.ApplicationServicesList) (map[string]*urisearch.APICache, [][]byte) {
	dependentCache := map[string]*urisearch.APICache{}
	caPool := [][]byte{}

	for _, service := range dependentServices {
		if service.Type != policy.ServiceHTTP {
			continue
		}
		if service.NetworkInfo.Ports.IsMultiPort() {
			zap.L().Error("Multiport services are not supported")
			continue
		}
		uricache := urisearch.NewAPICache(service.HTTPRules, service.ID, service.External)
		for _, fqdn := range service.NetworkInfo.FQDNs {
			dependentCache[fqdn+":"+service.NetworkInfo.Ports.String()] = uricache
		}
		for _, addr := range service.NetworkInfo.Addresses {
			dependentCache[addr.IP.String()+":"+service.NetworkInfo.Ports.String()] = uricache
		}
		if len(service.CACert) > 0 {
			caPool = append(caPool, service.CACert)
		}
	}
	return dependentCache, caPool
}

func (p *AppProxy) expandCAPool(externalCAs [][]byte) *x509.CertPool {
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		return p.systemCAPool
	}
	// We append the CA only if we are not in PSK mode as it doesn't provide a CA.
	if p.secrets.PublicSecrets().SecretsType() != secrets.PSKType {
		if ok := systemPool.AppendCertsFromPEM(p.secrets.PublicSecrets().CertAuthority()); !ok {
			return p.systemCAPool
		}
	}
	for _, ca := range externalCAs {
		systemPool.AppendCertsFromPEM(ca)
	}
	return systemPool
}
