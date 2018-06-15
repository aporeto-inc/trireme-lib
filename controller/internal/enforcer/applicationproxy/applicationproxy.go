package applicationproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/aporeto-inc/trireme-lib/utils/portspec"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/http"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/protomux"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/tcp"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"github.com/aporeto-inc/trireme-lib/controller/internal/portset"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/fqconfig"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/secrets"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/urisearch"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
	cryptohelpers "github.com/aporeto-inc/trireme-lib/utils/crypto"
	cryptoutils "github.com/aporeto-inc/trireme-lib/utils/crypto"
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
	netserver map[protomux.ListenerType]ServerInterface
}

// AppProxy maintains state for proxies connections from listen to backend.
type AppProxy struct {
	cert *tls.Certificate

	tokenaccessor     tokenaccessor.TokenAccessor
	collector         collector.EventCollector
	puFromID          cache.DataStore
	exposedAPICache   cache.DataStore
	dependentAPICache cache.DataStore
	jwtcache          cache.DataStore
	systemCAPool      *x509.CertPool
	secrets           secrets.Secrets

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
		collector:         c,
		tokenaccessor:     tp,
		secrets:           s,
		puFromID:          puFromID,
		cert:              certificate,
		clients:           cache.NewCache("clients"),
		exposedAPICache:   cache.NewCache("exposed services"),
		dependentAPICache: cache.NewCache("dependencies"),
		jwtcache:          cache.NewCache("jwtcache"),
		systemCAPool:      systemPool,
	}, nil
}

// Run starts all the network side proxies. Application side proxies will
// have to start during enforce in order to support multiple Linux processes.
func (p *AppProxy) Run(ctx context.Context) error {

	return nil
}

// Enforce implements enforcer.Enforcer interface. It will will create the necessary
// proxies for the particular PU.
func (p *AppProxy) Enforce(ctx context.Context, puID string, puInfo *policy.PUInfo) error {

	p.Lock()
	defer p.Unlock()

	// First update the caches with the new policy information.
	apicache, dependentCache, jwtcache, caPool, portCache := buildCaches(puInfo.Policy.ExposedServices(), puInfo.Policy.DependentServices())
	p.exposedAPICache.AddOrUpdate(puID, apicache)
	p.jwtcache.AddOrUpdate(puID, jwtcache)
	p.dependentAPICache.AddOrUpdate(puID, dependentCache)

	// For updates we need to update the certificates if we have new ones. Otherwise
	// we return. There is nothing else to do in case of policy update.
	if c, cerr := p.clients.Get(puID); cerr == nil {
		_, perr := p.processCertificateUpdates(puInfo, c.(*clientData), caPool)
		if perr != nil {
			return perr
		}
		return p.registerServices(c.(*clientData), puInfo)
	}

	// Create the network listener and cache it so that we can terminate it later.
	l, err := p.createNetworkListener(":" + puInfo.Runtime.Options().ProxyPort)
	if err != nil {
		return fmt.Errorf("Cannot create listener: %s", err)
	}

	// Create a new client entry and start the servers.
	client := &clientData{
		netserver: map[protomux.ListenerType]ServerInterface{},
	}
	client.protomux = protomux.NewMultiplexedListener(l, proxyMarkInt)

	// Listen to HTTP requests from the clients
	client.netserver[protomux.HTTPApplication], err = p.registerAndRun(ctx, puID, protomux.HTTPApplication, client.protomux, true)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", protomux.HTTPApplication, err)
	}

	// Listen to HTTPS requests only on the network side.
	client.netserver[protomux.HTTPSNetwork], err = p.registerAndRun(ctx, puID, protomux.HTTPSNetwork, client.protomux, false)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", protomux.HTTPSNetwork, err)
	}

	// TCP Requests for clients
	client.netserver[protomux.TCPApplication], err = p.registerAndRun(ctx, puID, protomux.TCPApplication, client.protomux, true)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", protomux.TCPApplication, err)
	}

	// TCP Requests from the network side
	client.netserver[protomux.TCPNetwork], err = p.registerAndRun(ctx, puID, protomux.TCPNetwork, client.protomux, false)
	if err != nil {
		return fmt.Errorf("Cannot create listener type %d: %s", protomux.TCPNetwork, err)
	}
	client.netserver[protomux.TCPNetwork].(*tcp.Proxy).UpdatePortCache(portCache)

	if err := p.registerServices(client, puInfo); err != nil {
		return fmt.Errorf("Unable to register services: %s ", err)
	}

	if _, err := p.processCertificateUpdates(puInfo, client, caPool); err != nil {
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

	if err := p.exposedAPICache.Remove(puID); err != nil {
		zap.L().Warn("Cannot find PU in the API cache")
	}

	if err := p.dependentAPICache.Remove(puID); err != nil {
		zap.L().Warn("Cannot find PU in the Dependent API cache")
	}

	if err := p.jwtcache.Remove(puID); err != nil {
		zap.L().Warn("Cannot find PU in the JWT cache")
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
			zap.L().Error("Unable to shutdown client server", zap.Error(err))
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

// GetPortSetInstance returns nil for the proxy
func (p *AppProxy) GetPortSetInstance() portset.PortSet {
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

	// Support for deprecated model. TODO : Remove
	proxiedServices := puInfo.Policy.ProxiedServices()
	for _, pair := range proxiedServices.PublicIPPortPair {
		service, err := serviceFromProxySet(pair)
		if err != nil {
			return err
		}
		if err := register.Add(service, protomux.TCPApplication, false); err != nil {
			return fmt.Errorf("Cannot add service: %s", err)
		}
	}

	for _, pair := range proxiedServices.PrivateIPPortPair {
		parts := strings.Split(pair, ",")
		if len(parts) != 2 {
			return fmt.Errorf("Invalid service: %s", pair)
		}
		ports, err := portspec.NewPortSpecFromString(parts[1], nil)
		if err != nil {
			return fmt.Errorf("Invalid service port: %s", err)
		}
		service := &common.Service{
			Ports:     ports,
			Protocol:  6,
			Addresses: []*net.IPNet{},
		}
		if err != nil {
			return err
		}
		if err := register.Add(service, protomux.TCPNetwork, true); err != nil {
			return fmt.Errorf("Cannot add service: %s", err)
		}
	}

	// Register the ExposedServices with the multiplexer.
	for _, service := range puInfo.Policy.ExposedServices() {
		if err := register.Add(service.PrivateNetworkInfo, serviceTypeToNetworkListenerType(service.Type), true); err != nil {
			return fmt.Errorf("Duplicate exposed service definitions: %s", err)
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
func (p *AppProxy) registerAndRun(ctx context.Context, puID string, ltype protomux.ListenerType, mux *protomux.MultiplexedListener, appproxy bool) (ServerInterface, error) {
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
		c := httpproxy.NewHTTPProxy(p.tokenaccessor, p.collector, puID, p.puFromID, p.systemCAPool, p.exposedAPICache, p.dependentAPICache, p.jwtcache, appproxy, proxyMarkInt, p.secrets)
		return c, c.RunNetworkServer(ctx, listener, encrypted)
	default:
		c := tcp.NewTCPProxy(p.tokenaccessor, p.collector, p.puFromID, puID, p.cert, p.systemCAPool)
		return c, c.RunNetworkServer(ctx, listener, encrypted)
	}
}

// createNetworkListener starts a network listener (traffic from network to PUs)
func (p *AppProxy) createNetworkListener(port string) (net.Listener, error) {

	return markedconn.SocketListener(port, proxyMarkInt)
}

// processCertificateUpdates processes the certificate information and updates
// the servers.
func (p *AppProxy) processCertificateUpdates(puInfo *policy.PUInfo, client *clientData, externalCAs [][]byte) (bool, error) {

	// If there are certificates provided, we will need to update them for the
	// services. If the certificates are nil, we ignore them.
	certPEM, keyPEM, caPEM := puInfo.Policy.ServiceCertificates()
	if certPEM == "" || keyPEM == "" {
		return false, nil
	}

	// Process any updates on the cert pool
	var caPool *x509.CertPool
	if caPEM != "" {
		caPool = cryptohelpers.LoadRootCertificates([]byte(caPEM))
	} else {
		caPool = p.systemCAPool
	}

	for _, caCert := range externalCAs {
		if !caPool.AppendCertsFromPEM(caCert) {
			zap.L().Warn("Failed to add CA certificate to chain")
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

func serviceTypeToNetworkListenerType(serviceType policy.ServiceType) protomux.ListenerType {
	switch serviceType {
	case policy.ServiceHTTP:
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

func buildCaches(exposedServices, dependentServices policy.ApplicationServicesList) (map[string]*urisearch.APICache, map[string]*urisearch.APICache, map[string]*x509.Certificate, [][]byte, map[int]string) {
	apicache := map[string]*urisearch.APICache{}
	jwtcache := map[string]*x509.Certificate{}
	dependentCache := map[string]*urisearch.APICache{}
	caPool := [][]byte{}

	for _, service := range exposedServices {
		if service.Type == policy.ServiceTCP {
			if port, err := service.PrivateNetworkInfo.Ports.SinglePort(); err == nil {
				portCache[int(port)] = service.ID
			}
			continue
		}
		if service.Type != policy.ServiceHTTP {
			continue
		}
		if service.NetworkInfo.Ports.IsMultiPort() {
			zap.L().Error("Multiport services are not supported")
			continue
		}
		ruleCache := urisearch.NewAPICache(service.HTTPRules, service.ID, false)
		for _, fqdn := range service.NetworkInfo.FQDNs {
			rhost := fqdn + ":" + service.NetworkInfo.Ports.String()
			apicache[rhost] = ruleCache
		}
		for _, addr := range service.NetworkInfo.Addresses {
			rhost := addr.IP.String() + ":" + service.NetworkInfo.Ports.String()
			apicache[rhost] = ruleCache
		}
		cert, err := cryptoutils.LoadCertificate(service.JWTCertificate)
		if err != nil {
			// We just ignore bad certificates and move on.
			zap.L().Debug("Unable to decode provided JWT PEM", zap.Error(err))
			continue
		}
		jwtcache[service.NetworkInfo.Ports.String()] = cert
	}

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
	return apicache, dependentCache, jwtcache, caPool, portCache
}

func serviceFromProxySet(pair string) (*common.Service, error) {
	parts := strings.Split(pair, ",")
	if len(parts) != 2 {
		return nil, fmt.Errorf("Invalid service: %s", pair)
	}

	_, ip, err := net.ParseCIDR(parts[0] + "/32")
	if err != nil {
		return nil, fmt.Errorf("Invalid service IP: %s", err)
	}
	ports, err := portspec.NewPortSpecFromString(parts[1], nil)
	if err != nil {
		return nil, fmt.Errorf("Invalid service port: %s", err)
	}

	return &common.Service{
		Ports:     ports,
		Protocol:  6,
		Addresses: []*net.IPNet{ip},
	}, nil
}
