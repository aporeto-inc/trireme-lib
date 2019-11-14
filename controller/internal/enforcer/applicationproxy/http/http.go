package httpproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aporeto-inc/oxy/forward"
	jwt "github.com/dgrijalva/jwt-go"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/apiauth"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/flowstats"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/metadata"
	"go.aporeto.io/trireme-lib/controller/pkg/bufferpool"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

type statsContextKeyType string

const (
	statsContextKey = statsContextKeyType("statsContext")

	// TriremeOIDCCallbackURI is the callback URI that must be presented by
	// any OIDC provider.
	TriremeOIDCCallbackURI = "/aporeto/oidc/callback"
)

// JWTClaims is the structure of the claims we are sending on the wire.
type JWTClaims struct {
	jwt.StandardClaims
	SourceID string
	Scopes   []string
	Profile  []string
}

type hookFunc func(w http.ResponseWriter, r *http.Request) (bool, error)

// Config maintains state for proxies connections from listen to backend.
type Config struct {
	cert             *tls.Certificate
	ca               *x509.CertPool
	keyPEM           string
	certPEM          string
	secrets          secrets.Secrets
	collector        collector.EventCollector
	puContext        string
	localIPs         map[string]struct{}
	applicationProxy bool
	mark             int
	server           *http.Server
	registry         *serviceregistry.Registry
	fwd              *forward.Forwarder
	fwdTLS           *forward.Forwarder
	tlsClientConfig  *tls.Config
	auth             *apiauth.Processor
	metadata         *metadata.Client
	tokenIssuer      common.ServiceTokenIssuer
	hooks            map[string]hookFunc
	sync.RWMutex
}

// NewHTTPProxy creates a new instance of proxy reate a new instance of Proxy
func NewHTTPProxy(
	c collector.EventCollector,
	puContext string,
	caPool *x509.CertPool,
	applicationProxy bool,
	mark int,
	secrets secrets.Secrets,
	registry *serviceregistry.Registry,
	tokenIssuer common.ServiceTokenIssuer,
) *Config {

	h := &Config{
		collector:        c,
		puContext:        puContext,
		ca:               caPool,
		applicationProxy: applicationProxy,
		mark:             mark,
		secrets:          secrets,
		localIPs:         markedconn.GetInterfaces(),
		registry:         registry,
		tlsClientConfig: &tls.Config{
			RootCAs: caPool,
		},
		auth:        apiauth.New(puContext, registry, secrets),
		metadata:    metadata.NewClient(puContext, registry, tokenIssuer),
		tokenIssuer: tokenIssuer,
	}

	hooks := map[string]hookFunc{
		common.MetadataHookPolicy:      h.policyHook,
		common.MetadataHookHealth:      h.healthHook,
		common.MetadataHookCertificate: h.certificateHook,
		common.MetadataHookKey:         h.keyHook,
		common.MetadataHookToken:       h.tokenHook,
		common.AWSHookInfo:             h.awsInfoHook,
		common.AWSHookRole:             h.awsTokenHook,
	}

	h.hooks = hooks

	return h
}

// clientTLSConfiguration calculates the right certificates and requests to the clients.
func (p *Config) clientTLSConfiguration(conn net.Conn, originalConfig *tls.Config) (*tls.Config, error) {
	fmt.Println("\n\n ABHI ** in clientTLSConfiguration for conn: ", conn.LocalAddr(), conn.RemoteAddr())
	if mconn, ok := conn.(*markedconn.ProxiedConnection); ok {
		ip, port := mconn.GetOriginalDestination()
		fmt.Println("Original IP:port ", ip, port)
		portContext, err := p.registry.RetrieveExposedServiceContext(ip, port, "")
		if err != nil {
			return nil, fmt.Errorf("Unknown service: %s", err)
		}
		fmt.Println("\n\n clientTLSConfiguration: portctx: ", portContext.ID, portContext.Service.NetworkInfo)
		fmt.Println("\n\n ABHI ** in clientTLSConfiguration auth type: ", portContext.Service.UserAuthorizationType, " mtls: ", policy.UserAuthorizationMutualTLS)
		if portContext.Service.UserAuthorizationType == policy.UserAuthorizationMutualTLS || portContext.Service.UserAuthorizationType == policy.UserAuthorizationJWT {
			clientCAs := p.ca
			if portContext.ClientTrustedRoots != nil {
				clientCAs = portContext.ClientTrustedRoots
			}
			config := p.newBaseTLSConfig()
			config.ClientAuth = tls.VerifyClientCertIfGiven
			config.ClientCAs = clientCAs
			return config, nil
		}
		fmt.Println("\n\n ABHI *** sending the originalConfig without certs")
		return originalConfig, nil
	}
	return nil, fmt.Errorf("Invalid connection")
}

// newBaseTLSConfig creates the new basic TLS configuration for the server.
func (p *Config) newBaseTLSConfig() *tls.Config {
	fmt.Println("\n\n ABHI configuring the newBaseTls")
	return &tls.Config{
		GetCertificate:           p.GetCertificateFunc(),
		NextProtos:               []string{"h2"},
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
		ClientAuth:               tls.RequestClientCert,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
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

	// If its an encrypted, wrap the listener in a TLS context. This is activated
	// for the listener from the network, but not for the listener from a PU.
	fmt.Println("\n\n ABHI RunNetworkServer with encrypted: ", encrypted)
	if encrypted {
		config := p.newBaseTLSConfig()
		config.GetConfigForClient = func(helloMsg *tls.ClientHelloInfo) (*tls.Config, error) {
			return p.clientTLSConfiguration(helloMsg.Conn, config)
		}
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			fmt.Println("\n\n ABHI in GetClientCertificate")
			return p.cert, nil
		}
		l = tls.NewListener(l, config)

	}
	fmt.Println("\n set the client cert in client config")
	p.tlsClientConfig.GetClientCertificate = p.GetClientCertificateFunc()
	//  func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	// 	fmt.Println("\n\n\t CLIENT_CERT: ABHI cleint *** in GetClientCertificate")
	// 	return p.cert, nil
	// }
	p.tlsClientConfig.GetCertificate = p.GetCertificateFunc()
	if p.cert != nil {
		fmt.Println("\n\n ABHI setting client cert", p.cert.Certificate)
		p.tlsClientConfig.Certificates = []tls.Certificate{*p.cert}
	}
	p.tlsClientConfig.MaxVersion = tls.VersionTLS12
	reportStats := func(ctx context.Context) {
		if state := ctx.Value(statsContextKey); state != nil {
			if r, ok := state.(*flowstats.ConnectionState); ok {
				r.Stats.Action = policy.Reject
				r.Stats.DropReason = collector.UnableToDial
				r.Stats.PolicyID = collector.DefaultEndPoint
				p.collector.CollectFlowEvent(r.Stats)
			}
		}
	}

	networkDialerWithContext := func(ctx context.Context, network, _ string) (net.Conn, error) {
		raddr, ok := ctx.Value(http.LocalAddrContextKey).(*net.TCPAddr)
		if !ok {
			reportStats(ctx)
			return nil, fmt.Errorf("invalid destination address")
		}
		conn, err := markedconn.DialMarkedWithContext(ctx, "tcp", raddr.String(), p.mark)
		if err != nil {
			reportStats(ctx)
			return nil, fmt.Errorf("Failed to dial remote: %s", err)
		}
		return conn, nil
	}

	appDialerWithContext := func(ctx context.Context, network, _ string) (net.Conn, error) {
		raddr, ok := ctx.Value(http.LocalAddrContextKey).(*net.TCPAddr)
		if !ok {
			reportStats(ctx)
			return nil, fmt.Errorf("invalid destination address")
		}
		pctx, err := p.registry.RetrieveExposedServiceContext(raddr.IP, raddr.Port, "")
		if err != nil {
			return nil, err
		}
		raddr.Port = pctx.TargetPort
		fmt.Println("\n\n ABHI, appDialerWithContext, creating a marked conn for ADDR: ", raddr.String())
		conn, err := markedconn.DialMarkedWithContext(ctx, "tcp", raddr.String(), p.mark)
		if err != nil {
			reportStats(ctx)
			return nil, fmt.Errorf("Failed to dial remote: %s", err)
		}
		return conn, nil
	}

	// Dial functions for the websockets.
	netDial := func(network, addr string) (net.Conn, error) {
		raddr, err := net.ResolveTCPAddr(network, addr)
		if err != nil {
			reportStats(context.Background())
			return nil, err
		}
		conn, err := markedconn.DialMarkedWithContext(ctx, "tcp", raddr.String(), p.mark)
		if err != nil {
			reportStats(context.Background())
			return nil, fmt.Errorf("Failed to dial remote: %s", err)
		}
		return conn, nil
	}

	appDial := func(network, addr string) (net.Conn, error) {
		raddr, err := net.ResolveTCPAddr(network, addr)
		if err != nil {
			reportStats(context.Background())
			return nil, err
		}
		pctx, err := p.registry.RetrieveExposedServiceContext(raddr.IP, raddr.Port, "")
		if err != nil {
			return nil, err
		}
		raddr.Port = pctx.TargetPort
		conn, err := markedconn.DialMarkedWithContext(ctx, "tcp", raddr.String(), p.mark)
		if err != nil {
			reportStats(context.Background())
			return nil, fmt.Errorf("Failed to dial remote: %s", err)
		}
		return conn, nil
	}

	// Create an encrypted downstream transport. We will mark the downstream connection
	// to let the iptables rule capture it.
	encryptedTransport := &http.Transport{
		TLSClientConfig:     p.tlsClientConfig,
		DialContext:         networkDialerWithContext,
		MaxIdleConnsPerHost: 2000,
		MaxIdleConns:        2000,
	}

	// Create an unencrypted transport for talking to the application. If encryption
	// is selected do not verify the certificates. This is supposed to be inside the
	// same system. TODO: use pinned certificates.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { // nolint
				return p.cert, nil
			},
		},
		DialContext:         appDialerWithContext,
		MaxIdleConns:        2000,
		MaxIdleConnsPerHost: 2000,
	}

	// Create the proxies dowards the network and the application.
	var err error
	p.fwdTLS, err = forward.New(
		forward.RoundTripper(encryptedTransport),
		forward.WebsocketTLSClientConfig(&tls.Config{RootCAs: p.ca}),
		forward.WebSocketNetDial(netDial),
		forward.BufferPool(bufferpool.NewPool(32*1204)),
		forward.ErrorHandler(TriremeHTTPErrHandler{}),
	)
	if err != nil {
		return fmt.Errorf("Cannot initialize encrypted transport: %s", err)
	}

	p.fwd, err = forward.New(
		forward.RoundTripper(NewTriremeRoundTripper(transport)),
		forward.WebsocketTLSClientConfig(&tls.Config{InsecureSkipVerify: true}),
		forward.WebSocketNetDial(appDial),
		forward.BufferPool(bufferpool.NewPool(32*1204)),
		forward.ErrorHandler(TriremeHTTPErrHandler{}),
	)
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
		p.server.Close() // nolint
	}()
	fmt.Println("\n\n ABHI: now start serving on the listener: ", l.Addr())
	go p.server.Serve(l) // nolint

	return nil
}

// ShutDown terminates the server.
func (p *Config) ShutDown() error {
	return p.server.Close()
}

// UpdateSecrets updates the secrets
func (p *Config) UpdateSecrets(cert *tls.Certificate, caPool *x509.CertPool, s secrets.Secrets, certPEM, keyPEM string) {
	p.Lock()
	p.cert = cert
	p.ca = caPool
	p.secrets = s
	p.certPEM = certPEM
	p.keyPEM = keyPEM
	p.tlsClientConfig.RootCAs = caPool
	p.Unlock()

	p.metadata.UpdateSecrets([]byte(certPEM), []byte(keyPEM))
	p.auth.UpdateSecrets(s)
}

func (p *Config) GetClientCertificateFunc() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if p.cert != nil {
			cert, err := x509.ParseCertificate(p.cert.Certificate[0])
			if err != nil {
				zap.L().Error("SDS Server: Cannot build the cert chain")
			}
			if cert != nil {
				by, _ := x509CertToPem(cert)
				pemCert, err := buildCertChain(by, p.secrets.PublicSecrets().CertAuthority())
				if err != nil {
					zap.L().Error("SDS Server: Cannot build the cert chain")
				}
				var certChain tls.Certificate
				//certPEMBlock := []byte(rootcaBundle)
				var certDERBlock *pem.Block
				for {
					certDERBlock, pemCert = pem.Decode(pemCert)
					if certDERBlock == nil {
						break
					}
					if certDERBlock.Type == "CERTIFICATE" {
						certChain.Certificate = append(certChain.Certificate, certDERBlock.Bytes)
					}
				}
				certChain.PrivateKey = p.cert.PrivateKey
				//certChain.Certificate
				return &certChain, nil
			}
			return p.cert, nil
		}
		return nil, nil
	}
}

// GetCertificateFunc implements the TLS interface for getting the certificate. This
// allows us to update the certificates of the connection on the fly.
func (p *Config) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		p.RLock()
		defer p.RUnlock()
		// First we check if this is a direct access to the public port. In this case
		// we will use the service public certificate. Otherwise, we will return the
		// enforcer certificate since this is internal access.
		if mconn, ok := clientHello.Conn.(*markedconn.ProxiedConnection); ok {
			ip, port := mconn.GetOriginalDestination()
			portContext, err := p.registry.RetrieveExposedServiceContext(ip, port, "")
			if err != nil {
				return nil, fmt.Errorf("service not available: %s %d", ip.String(), port)
			}
			service := portContext.Service
			if service.PublicNetworkInfo != nil && service.PublicNetworkInfo.Ports.Min == uint16(port) && len(service.PublicServiceCertificate) > 0 {
				tlsCert, err := tls.X509KeyPair(service.PublicServiceCertificate, service.PublicServiceCertificateKey)
				if err != nil {
					return nil, fmt.Errorf("failed to parse server certificate: %s", err)
				}
				return &tlsCert, nil
			}
		}
		if p.cert != nil {
			tmp := p.newBaseTLSConfig()
			fmt.Println("\n\n the cipher suites by client are: ", clientHello.CipherSuites, "aporeto cipher suites: ", tmp.CipherSuites)
			//p.pickCipherSuite(clientHello)
			cert, err := x509.ParseCertificate(p.cert.Certificate[0])
			if err != nil {
				fmt.Println("\n\n ABHI error while parsing the cert")
			}
			if cert != nil {
				by, _ := x509CertToPem(cert)
				fmt.Println(string(by), "apo-ca:", string(p.secrets.PublicSecrets().CertAuthority()))
				pemCert, err := buildCertChain(by, p.secrets.PublicSecrets().CertAuthority())
				if err != nil {
					zap.L().Error("SDS Server: Cannot build the cert chain")
				}
				// fmt.Println(string(pemCert))
				// fmt.Println("\n\n ABHI now build the cert chain acccordingly to envoy")
				var certChain tls.Certificate
				//certPEMBlock := []byte(rootcaBundle)
				var certDERBlock *pem.Block
				for {
					certDERBlock, pemCert = pem.Decode(pemCert)
					if certDERBlock == nil {
						break
					}
					if certDERBlock.Type == "CERTIFICATE" {
						certChain.Certificate = append(certChain.Certificate, certDERBlock.Bytes)
					}
				}
				certChain.PrivateKey = p.cert.PrivateKey
				//certChain.Certificate
				return &certChain, nil
			}
			return p.cert, nil
		}
		return nil, fmt.Errorf("no cert available - cert is nil")
	}
}

func buildCertChain(certPEM, caPEM []byte) ([]byte, error) {
	zap.L().Debug("SDS Server:  BEFORE in buildCertChain certPEM: ", zap.String("certPEM:", string(certPEM)), zap.String("caPEM: ", string(caPEM)))
	certChain := []*x509.Certificate{}
	//certPEMBlock := caPEM
	clientPEMBlock := certPEM
	derBlock, _ := pem.Decode(clientPEMBlock)
	if derBlock != nil {
		if derBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(derBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certChain = append(certChain, cert)
		} else {
			return nil, fmt.Errorf("invalid pem block type: %s", derBlock.Type)
		}
	}
	var certDERBlock *pem.Block
	for {
		certDERBlock, caPEM = pem.Decode(caPEM)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(certDERBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certChain = append(certChain, cert)
		} else {
			return nil, fmt.Errorf("invalid pem block type: %s", certDERBlock.Type)
		}
	}
	by, _ := x509CertChainToPem(certChain)
	zap.L().Debug("SDS Server: After building the cert chain: ", zap.String("certChain: ", string(by)))
	return x509CertChainToPem(certChain)
}

// x509CertChainToPem converts chain of x509 certs to byte.
func x509CertChainToPem(certChain []*x509.Certificate) ([]byte, error) {
	var pemBytes bytes.Buffer
	for _, cert := range certChain {
		if err := pem.Encode(&pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return nil, err
		}
	}
	return pemBytes.Bytes(), nil
}

// x509CertToPem converts x509 to byte.
func x509CertToPem(cert *x509.Certificate) ([]byte, error) {
	var pemBytes bytes.Buffer
	if err := pem.Encode(&pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return nil, err
	}
	return pemBytes.Bytes(), nil
}
func (p *Config) processAppRequest(w http.ResponseWriter, r *http.Request) {

	zap.L().Debug("Processing Application Request", zap.String("URI", r.RequestURI), zap.String("Host", r.Host))
	fmt.Println("\n\n IN app request")
	originalDestination := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	fmt.Println("ABHI Processing App request: uri, host, dest: ", r.RequestURI, r.Host, originalDestination, r.Method)
	// Authorize the request by calling the authorizer library.
	authRequest := &apiauth.Request{
		OriginalDestination: originalDestination,
		Method:              r.Method,
		URL:                 r.URL,
		RequestURI:          r.RequestURI,
	}

	resp, err := p.auth.ApplicationRequest(authRequest)
	if err != nil {
		if resp.PUContext != nil {
			state := flowstats.NewAppConnectionState(p.puContext, r, authRequest, resp)
			state.Stats.Action = resp.Action
			state.Stats.PolicyID = resp.NetworkPolicyID
			p.collector.CollectFlowEvent(state.Stats)
		}
		http.Error(w, err.Error(), err.(*apiauth.AuthError).Status())
		return
	}

	state := flowstats.NewAppConnectionState(p.puContext, r, authRequest, resp)
	if resp.External {
		defer p.collector.CollectFlowEvent(state.Stats)
	}

	if resp.HookMethod != "" {
		if hook, ok := p.hooks[resp.HookMethod]; ok {
			if isHook, err := hook(w, r); err != nil || isHook {
				if err != nil {
					state.Stats.Action = policy.Reject
					state.Stats.DropReason = collector.PolicyDrop
				}
				return
			}
		} else {
			http.Error(w, "Invalid hook configuration", http.StatusInternalServerError)
			return
		}
	}

	httpScheme := "http://"
	if resp.TLSListener {
		httpScheme = "https://"
	}

	// Create the new target URL based on the Host parameter that we had.
	r.URL, err = url.ParseRequestURI(httpScheme + r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid destination host name"), http.StatusUnprocessableEntity)
		return
	}

	// Add the headers with the authorization parameters and public key. The other side
	// must validate our public key.
	r.Header.Add("X-APORETO-KEY", string(p.secrets.TransmittedKey()))
	r.Header.Add("X-APORETO-AUTH", resp.Token)

	contextWithStats := context.WithValue(r.Context(), statsContextKey, state)
	// Forward the request.
	fmt.Println("forward the request")
	p.fwdTLS.ServeHTTP(w, r.WithContext(contextWithStats))
}

func (p *Config) processNetRequest(w http.ResponseWriter, r *http.Request) {

	zap.L().Debug("Processing Network Request", zap.String("URI", r.RequestURI), zap.String("Host", r.Host))
	fmt.Println("\n\n ABHI in network request")
	originalDestination := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)

	sourceAddress, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		zap.L().Error("Internal server error - cannot determine source address information", zap.Error(err))
		http.Error(w, fmt.Sprintf("Invalid network information"), http.StatusForbidden)
		return
	}

	requestCookie, _ := r.Cookie("X-APORETO-AUTH") // nolint errcheck
	fmt.Println("ABHI network Request: uri, host, orgDst, srcAddr: ", r.RequestURI, r.Host, originalDestination, sourceAddress)
	request := &apiauth.Request{
		OriginalDestination: originalDestination,
		SourceAddress:       sourceAddress,
		Header:              r.Header,
		URL:                 r.URL,
		Method:              r.Method,
		RequestURI:          r.RequestURI,
		Cookie:              requestCookie,
		TLS:                 r.TLS,
	}

	response, err := p.auth.NetworkRequest(r.Context(), request)

	var userID string
	if response != nil && len(response.UserAttributes) > 0 {
		userData := &collector.UserRecord{
			Namespace: response.Namespace,
			Claims:    response.UserAttributes,
		}
		p.collector.CollectUserEvent(userData)
		userID = userData.ID
	}

	state := flowstats.NewNetworkConnectionState(p.puContext, userID, request, response)
	defer p.collector.CollectFlowEvent(state.Stats)

	if err != nil {
		fmt.Println("ABHI network request error: ", err)
		zap.L().Debug("Authorization error",
			zap.Reflect("Error", err),
			zap.String("URI", r.RequestURI),
			zap.String("Host", r.Host),
		)
		authError, ok := err.(*apiauth.AuthError)
		if !ok {
			http.Error(w, "Internal type error", http.StatusInternalServerError)
			return
		}

		if response == nil {
			// Basic errors are captured here.
			http.Error(w, authError.Message(), authError.Status())
			return
		}

		if !response.Redirect {
			// If there is no redirect, we also return an error.
			http.Error(w, authError.Message(), authError.Status())
			return
		}

		// Redirect logic. Populate information here. This is forcing a
		// redirect rather than an error.
		if response.Cookie != nil {
			http.SetCookie(w, response.Cookie)
		}
		w.Header().Add("Location", response.RedirectURI)
		http.Error(w, response.Data, authError.Status())

		return
	}

	// Select as http or https for communication with listening service.
	httpPrefix := "http://"
	if response.TLSListener {
		httpPrefix = "https://"
	}

	// Create the target URI. Websocket Gorilla proxy takes it from the URL. For normal
	// connections we don't want that.
	if forward.IsWebsocketRequest(r) {
		r.URL, err = url.ParseRequestURI(httpPrefix + originalDestination.String())
	} else {
		r.URL, err = url.ParseRequestURI(httpPrefix + r.Host)
	}
	if err != nil {
		state.Stats.DropReason = collector.InvalidFormat
		http.Error(w, fmt.Sprintf("Invalid HTTP Host parameter: %s", err), http.StatusBadRequest)
		return
	}

	// Update the request headers with the user attributes as defined by the mappings
	r.Header = response.Header

	// Update the statistics and forward the request. We always encrypt downstream
	state.Stats.Action = policy.Accept | policy.Encrypt

	// // Treat the remote proxy scenario where the destination IPs are in a remote
	// // host. Check of network rules that allow this transfer and report the corresponding
	// // flows.
	// if _, ok := p.localIPs[originalDestination.IP.String()]; !ok {
	// 	_, action, err := pctx.PUContext.ApplicationACLPolicyFromAddr(originalDestination.IP, uint16(originalDestination.Port))
	// 	if err != nil || action.Action.Rejected() {
	// 		defer p.collector.CollectFlowEvent(reportDownStream(state.stats, action))
	// 		http.Error(w, fmt.Sprintf("Access denied by network policy to downstream IP: %s", originalDestination.IP.String()), http.StatusNetworkAuthenticationRequired)
	// 		return
	// 	}
	// 	if action.Action.Accepted() {
	// 		defer p.collector.CollectFlowEvent(reportDownStream(state.stats, action))
	// 	}
	// }
	fmt.Println("Forward the request")
	contextWithStats := context.WithValue(r.Context(), statsContextKey, state)
	p.fwd.ServeHTTP(w, r.WithContext(contextWithStats))
	zap.L().Debug("Forwarding Request", zap.String("URI", r.RequestURI), zap.String("Host", r.Host))
}

func (p *Config) policyHook(w http.ResponseWriter, r *http.Request) (bool, error) {
	if r.Header.Get(common.MetadataKey) != common.MetadataValue {
		http.Error(w, fmt.Sprintf("unauthorized request for policy"), http.StatusForbidden)
		return true, fmt.Errorf("unauthorized")
	}

	data, _, err := p.metadata.GetCurrentPolicy()
	if err != nil {
		http.Error(w, fmt.Sprintf("Unable to retrieve current policy"), http.StatusInternalServerError)
		return true, err
	}
	if _, err := w.Write(data); err != nil {
		zap.L().Error("Unable to write policy response")
	}

	return true, nil
}

func (p *Config) certificateHook(w http.ResponseWriter, r *http.Request) (bool, error) {
	if r.Header.Get(common.MetadataKey) != common.MetadataValue {
		http.Error(w, fmt.Sprintf("unauthorized request for certificate"), http.StatusForbidden)
		return true, fmt.Errorf("unauthorized")
	}

	if _, err := w.Write(p.metadata.GetCertificate()); err != nil {
		zap.L().Error("Unable to write response")
	}

	return true, nil
}

func (p *Config) keyHook(w http.ResponseWriter, r *http.Request) (bool, error) {
	if r.Header.Get(common.MetadataKey) != common.MetadataValue {
		http.Error(w, fmt.Sprintf("unauthorized request for private key"), http.StatusForbidden)
		return true, fmt.Errorf("unauthorized")
	}

	if _, err := w.Write(p.metadata.GetPrivateKey()); err != nil {
		zap.L().Error("Unable to write response")
	}

	return true, nil
}

func (p *Config) healthHook(w http.ResponseWriter, r *http.Request) (bool, error) {

	// Health hook will only return ok if the current policy is already populated.
	plc, _, err := p.metadata.GetCurrentPolicy()
	if err != nil || plc == nil {
		http.Error(w, fmt.Sprintf("Unable to retrieve current policy"), http.StatusInternalServerError)
		return true, err
	}

	if _, err := w.Write([]byte("OK\n")); err != nil {
		zap.L().Error("Unable to write response to health API")
	}
	return true, nil
}

func (p *Config) tokenHook(w http.ResponseWriter, r *http.Request) (bool, error) {

	if r.Header.Get(common.MetadataKey) != common.MetadataValue {
		http.Error(w, fmt.Sprintf("unauthorized request for token"), http.StatusForbidden)
		return true, fmt.Errorf("unauthorized")
	}

	audience := r.URL.Query().Get("audience")
	validityString := r.URL.Query().Get("validity")

	validity := time.Minute * 60
	var err error
	if validityString != "" {
		validity, err = time.ParseDuration(validityString)
		if err != nil {
			http.Error(w, "Invalid validity time requested. Please use notation of number+unit. Example: `10m`", http.StatusUnprocessableEntity)
			return true, nil
		}
	}

	token, err := p.tokenIssuer.Issue(r.Context(), p.puContext, common.ServiceTokenTypeOAUTH, audience, validity)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unable to issue token: %s", err), http.StatusBadRequest)
		return true, nil
	}

	if _, err := w.Write([]byte(token)); err != nil {
		zap.L().Error("Unable to write response on token API")
	}
	return true, nil
}

func (p *Config) awsInfoHook(w http.ResponseWriter, r *http.Request) (bool, error) {

	if err := validateAWSHeaders(r); err != nil {
		http.Error(w, fmt.Sprintf("invalid user agent: %s", err), http.StatusForbidden)
		return true, err
	}

	awsRole, id, err := p.awsRole()
	if err != nil {
		return true, err
	}

	type info struct {
		Code               string    `json:"Code,omitempty"`
		LastUpdated        time.Time `json:"LastUpdated,omitempty"`
		InstanceProfileArn string    `json:"InstanceProfileArn,omitempty"`
		InstanceProfileID  string    `json:"InstanceProfileId,omitempty"`
	}

	out := &info{
		Code:               "Success",
		LastUpdated:        time.Now(),
		InstanceProfileArn: awsRole,
		InstanceProfileID:  id,
	}

	data, err := json.MarshalIndent(out, " ", " ")
	if err != nil {
		return true, fmt.Errorf("error in marshall of info: %s", err)
	}

	if _, err = w.Write(data); err != nil {
		return true, fmt.Errorf("unable to write data response: %s", err)
	}

	return true, nil
}

func (p *Config) awsTokenHook(w http.ResponseWriter, r *http.Request) (bool, error) {

	if err := validateAWSHeaders(r); err != nil {
		http.Error(w, fmt.Sprintf("invalid user agent: %s", err), http.StatusForbidden)
		return true, err
	}

	awsRole, id, err := p.awsRole()
	if err != nil {
		return true, err
	}

	awsRoleParts := strings.Split(awsRole, "/")
	if len(awsRoleParts) == 0 {
		http.Error(w, fmt.Sprintf("invalid role: %s", err), http.StatusNotFound)
		return true, fmt.Errorf("invalid role: %s", awsRole)
	}

	awsRoleName := awsRoleParts[len(awsRoleParts)-1]

	if strings.HasSuffix(r.RequestURI, "security-credentials/") {
		if _, err := w.Write([]byte(awsRoleName)); err != nil {
			return true, err
		}
		return true, nil
	}

	if !strings.HasSuffix(r.RequestURI, "security-credentials/"+awsRoleName) {
		http.Error(w, fmt.Sprintf("not found"), http.StatusNotFound)
		return true, fmt.Errorf("not found")
	}

	token, err := p.tokenIssuer.Issue(r.Context(), id, common.ServiceTokenTypeAWS, awsRole, time.Hour)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unable to issue token: %s", err), http.StatusBadRequest)
		return true, nil
	}

	if _, err := w.Write([]byte(token)); err != nil {
		zap.L().Error("Unable to write response on token API")
	}
	return true, nil
}

func (p *Config) awsRole() (string, string, error) {

	_, plc, err := p.metadata.GetCurrentPolicy()
	if err != nil {
		return "", "", err
	}

	awsRole := ""
	for _, scope := range plc.Scopes {
		if strings.HasPrefix(scope, common.AWSRoleARNPrefix) {
			if awsRole != "" && awsRole != scope[len(common.AWSRolePrefix):] {
				return "", "", fmt.Errorf("overlapping roles detected")
			}
			awsRole = scope[len(common.AWSRolePrefix):]
		}
	}

	if awsRole == "" {
		return "", "", fmt.Errorf("role not found")
	}

	return awsRole, plc.ManagementID, nil
}

var (
	allowedAgents = []string{"aws-cli/", "aws-chalice/", "Boto3/", "Botocore/", "aws-sdk-"}
)

func validateAWSHeaders(r *http.Request) error {

	userAgent, ok := r.Header["User-Agent"]
	if !ok {
		return fmt.Errorf("no user-agent provided")
	}

	for _, u := range userAgent {
		for _, t := range allowedAgents {
			if strings.HasPrefix(u, t) {
				return nil
			}
		}
	}

	return fmt.Errorf("invalid user agent: %v", userAgent)
}

// func reportDownStream(record *collector.FlowRecord, action *policy.FlowPolicy) *collector.FlowRecord {
// 	return &collector.FlowRecord{
// 		ContextID: record.ContextID,
// 		Destination: &collector.EndPoint{
// 			URI:        record.Destination.URI,
// 			HTTPMethod: record.Destination.HTTPMethod,
// 			Type:       collector.EndPointTypeExternalIP,
// 			Port:       record.Destination.Port,
// 			IP:         record.Destination.IP,
// 			ID:         action.ServiceID,
// 		},
// 		Source: &collector.EndPoint{
// 			Type: record.Destination.Type,
// 			ID:   record.Destination.ID,
// 			IP:   "0.0.0.0",
// 		},
// 		Action:      action.Action,
// 		L4Protocol:  record.L4Protocol,
// 		ServiceType: record.ServiceType,
// 		ServiceID:   record.ServiceID,
// 		Tags:        record.Tags,
// 		PolicyID:    action.PolicyID,
// 		Count:       1,
// 	}
// }
