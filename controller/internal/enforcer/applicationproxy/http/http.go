package httpproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/connection"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/pucontext"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
	"go.uber.org/zap"

	"github.com/vulcand/oxy/forward"
)

const (
	sockOptOriginalDst = 80
	proxyMarkInt       = 0x40 //Duplicated from supervisor/iptablesctrl refer to it

)

type secretsPEM interface {
	AuthPEM() []byte
	TransmittedPEM() []byte
	EncodingPEM() []byte
}

// Config maintains state for proxies connections from listen to backend.
type Config struct {
	clientPort string
	serverPort string

	cert *tls.Certificate
	ca   *x509.CertPool

	tokenaccessor     tokenaccessor.TokenAccessor
	collector         collector.EventCollector
	puContext         string
	puFromIDCache     cache.DataStore
	exposedServices   cache.DataStore
	dependentServices cache.DataStore

	applicationProxy bool

	server *http.Server
	fwd    *forward.Forwarder
	fwdTLS *forward.Forwarder
	sync.RWMutex
}

// NewHTTPProxy creates a new instance of proxy reate a new instance of Proxy
func NewHTTPProxy(
	tp tokenaccessor.TokenAccessor,
	c collector.EventCollector,
	puContext string,
	puFromIDCache cache.DataStore,
	certificate *tls.Certificate,
	caPool *x509.CertPool,
	exposedServices cache.DataStore,
	dependentServices cache.DataStore,
	applicationProxy bool,
) *Config {

	return &Config{
		collector:         c,
		tokenaccessor:     tp,
		puFromIDCache:     puFromIDCache,
		puContext:         puContext,
		cert:              certificate,
		ca:                caPool,
		exposedServices:   exposedServices,
		dependentServices: dependentServices,
		applicationProxy:  applicationProxy,
	}
}

// RunNetworkServer runs an HTTP network server. If TLS is needed, the
// listener should be already a TLS listener.
func (p *Config) RunNetworkServer(ctx context.Context, l net.Listener, encrypted bool) error {

	p.Lock()
	defer p.Unlock()

	if p.server != nil {
		return fmt.Errorf("Server already running")
	}

	// If its an encrypted, wrap it in a TLS context.
	if encrypted {
		config := &tls.Config{
			GetCertificate: p.GetCertificateFunc(),
		}
		l = tls.NewListener(l, config)
	}

	// Create an encrypted downstream transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: p.ca,
		},
	}

	var err error
	p.fwdTLS, err = forward.New(forward.RoundTripper(transport))
	if err != nil {
		return fmt.Errorf("Cannot initialize encrypted transport: %s", err)
	}

	p.fwd, err = forward.New()
	if err != nil {
		return fmt.Errorf("Cannot initialize unencrypted transport: %s", err)
	}

	processor := p.processAppRequest
	if !p.applicationProxy {
		processor = p.processNetRequest
	}

	p.server = &http.Server{
		Handler: http.HandlerFunc(processor),
	}

	go func() {
		<-ctx.Done()
		p.server.Close()
	}()

	go p.server.Serve(l)

	return nil
}

// ShutDown terminates the server.
func (p *Config) ShutDown() error {
	return p.server.Close()
}

// UpdateSecrets updates the secrets
func (p *Config) UpdateSecrets(cert *tls.Certificate, caPool *x509.CertPool) {
	p.Lock()
	defer p.Unlock()

	p.cert = cert
	p.ca = caPool
}

// GetCertificateFunc implements the TLS interface for getting the certificate. This
// allows us to update the certificates of the connection on the fly.
func (p *Config) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		p.RLock()
		defer p.RUnlock()
		if p.cert != nil {
			return p.cert, nil
		}
		return nil, fmt.Errorf("no cert available")
	}
}

func (p *Config) processAppRequest(w http.ResponseWriter, r *http.Request) {
	pu, err := p.puFromIDCache.Get(p.puContext)
	if err != nil {
		zap.L().Error("Cannot find policy, dropping request")
		http.Error(w, fmt.Sprintf("Cannot handle request: %s", err), http.StatusInternalServerError)
	}

	puContext := pu.(*pucontext.PUContext)
	token, err := p.createClientToken(puContext)
	if err != nil {
		http.Error(w, fmt.Sprintf("Cannot handle request: %s", err), http.StatusForbidden)
	}

	w.Header().Set("X-APORETO-AUTH", string(token))
	p.fwdTLS.ServeHTTP(w, r)
}

func (p *Config) processNetRequest(w http.ResponseWriter, r *http.Request) {
	_, err := p.puFromIDCache.Get(p.puContext)
	if err != nil {
		zap.L().Error("Cannot find policy, dropping request")
		http.Error(w, fmt.Sprintf("Cannot handle request: %s", err), http.StatusForbidden)
	}

	token := r.Header.Get("X-APORETO-AUTH")
	if token != "" {
		fmt.Println("TODO - do the matching now")
	}
	p.fwd.ServeHTTP(w, r)
}

func (p *Config) createClientToken(puContext *pucontext.PUContext) ([]byte, error) {
	conn := connection.NewProxyConnection()
	return p.tokenaccessor.CreateSynPacketToken(puContext, &conn.Auth)
}
