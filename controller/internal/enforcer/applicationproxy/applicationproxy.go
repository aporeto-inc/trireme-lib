package applicationproxy

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"

	"github.com/aporeto-inc/enforcerd/certmanager"
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/http"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/protomux"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/tcp"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"github.com/aporeto-inc/trireme-lib/controller/internal/portset"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/fqconfig"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/secrets"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
	cryptohelpers "github.com/aporeto-inc/trireme-lib/utils/crypto"
	"go.uber.org/zap"
)

const (
	proxyMarkInt = 0x40 //Duplicated from supervisor/iptablesctrl refer to it

)

// ServerInterface describes the methods required by an application processor.
type ServerInterface interface {
	RunNetworkServer(ctx context.Context, l net.Listener, encrypted bool) error
	UpdateSecrets(cert *tls.Certificate, ca *x509.CertPool)
	ShutDown() error
}

type secretsPEM interface {
	AuthPEM() []byte
	TransmittedPEM() []byte
	EncodingPEM() []byte
}

type clientData struct {
	protomux  *protomux.MultiplexedListener
	netserver map[protomux.ListenerType]ServerInterface
}

// AppProxy maintains state for proxies connections from listen to backend.
type AppProxy struct {
	serverPort string

	cert *tls.Certificate
	ca   *x509.CertPool

	tokenaccessor       tokenaccessor.TokenAccessor
	collector           collector.EventCollector
	puFromID            cache.DataStore
	exposedServices     cache.DataStore
	dependentServices   cache.DataStore
	servicesCertificate *x509.Certificate
	servicesKey         crypto.PrivateKey
	systemCAPool        *x509.CertPool

	protoMux  *protomux.MultiplexedListener
	netserver map[protomux.ListenerType]ServerInterface

	clients cache.DataStore
	sync.RWMutex
}

// NewAppProxy creates a new instance of the application proxy.
func NewAppProxy(tp tokenaccessor.TokenAccessor, c collector.EventCollector, puFromID cache.DataStore, certificate *tls.Certificate, caPool *x509.CertPool) (*AppProxy, error) {

	systemPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	return &AppProxy{
		collector:         c,
		tokenaccessor:     tp,
		puFromID:          puFromID,
		cert:              certificate,
		ca:                caPool,
		clients:           cache.NewCache("clients"),
		exposedServices:   cache.NewCache("exposed services"),
		dependentServices: cache.NewCache("dependencies"),
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

	// For updates we need to update the policy and certificates.
	if c, err := p.clients.Get(puID); err == nil {
		// Update all the certificates from the new policy.
		client := c.(*clientData)
		for _, server := range client.netserver {
			certPEM, keyPEM, caPEM := puInfo.Policy.ServiceCertificates()
			if certPEM == "" || keyPEM == "" {
				return nil
			}

			certificate, err := certmanager.ReadCertificatePEMFromData([]byte(certPEM))
			if err != nil {
				return fmt.Errorf("Unable to decode certificate: %s", err)
			}

			var caPool *x509.CertPool
			if caPEM != "" {
				caPool = cryptohelpers.LoadRootCertificates([]byte(caPEM))
			} else {
				caPool = p.systemCAPool
			}

			key, err := cryptohelpers.LoadEllipticCurveKey([]byte(keyPEM))
			if err != nil {
				return err
			}

			tlsCert, err := certmanager.ToTLSCertificate(certificate, key)
			if err != nil {
				return fmt.Errorf("Failed to update certificates during enforcement: %s", err)
			}
			server.UpdateSecrets(&tlsCert, caPool)
		}
		return nil
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

	// Register the ExposedServices with the multiplexer.
	for _, service := range puInfo.Policy.ExposedServices() {
		client.protomux.RegisterService(service.NetworkInfo, serviceTypeToNetworkListenerType(service.Type))
	}

	// Register the DependentServices with the multiplexer.
	for _, service := range puInfo.Policy.DependentServices() {
		fmt.Println("Registering services", service.NetworkInfo, serviceTypeToApplicationListenerType(service.Type))
		client.protomux.RegisterService(service.NetworkInfo, serviceTypeToApplicationListenerType(service.Type))
	}

	// Add the client to the cache
	p.clients.AddOrUpdate(puID, client)

	// Start the connection multiplexer
	go client.protomux.Serve(ctx)

	return nil
}

// Unenforce implements enforcer.Enforcer interface. It will shutdown the app side
// of the proxy.
func (p *AppProxy) Unenforce(ctx context.Context, puID string) error {
	p.Lock()
	defer p.Unlock()

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
	pkier := secret.(secretsPEM)
	var certificate tls.Certificate
	var err error
	if secret.Type() != secrets.PSKType {
		if certificate, err = tls.X509KeyPair(pkier.TransmittedPEM(), pkier.EncodingPEM()); err != nil {
			return fmt.Errorf("Cannot extract cert and key from secrets %s", err)
		}
		p.Lock()
		p.cert = &certificate
		p.Unlock()
	}
	return nil
}

// GetCertificateFunc implements the TLS interface for getting the certificate.
func (p *AppProxy) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		p.RLock()
		defer p.RUnlock()
		return p.cert, nil
	}
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
		c := httpproxy.NewHTTPProxy(p.tokenaccessor, p.collector, puID, p.puFromID, p.cert, p.ca, p.exposedServices, p.dependentServices, appproxy, proxyMarkInt)
		return c, c.RunNetworkServer(ctx, listener, encrypted)
	default:
		c := tcp.NewTCPProxy(p.tokenaccessor, p.collector, p.puFromID, puID, p.cert, p.ca, p.exposedServices, p.dependentServices)
		return c, c.RunNetworkServer(ctx, listener, encrypted)
	}
}

// createNetworkListener starts a network listener (traffic from network to PUs)
func (p *AppProxy) createNetworkListener(port string) (net.Listener, error) {

	addr, err := net.ResolveTCPAddr("tcp", port)
	if err != nil {
		return nil, fmt.Errorf("Cannot resolve address: %s", err)
	}

	return net.ListenTCP("tcp", addr)
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
