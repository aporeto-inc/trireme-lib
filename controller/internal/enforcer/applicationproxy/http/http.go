package httpproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/servicetokens"
	"go.aporeto.io/trireme-lib/controller/pkg/urisearch"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

type statsContextKeyType string

const (
	defaultValidity = 60 * time.Second
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
) *Config {

	return &Config{
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
	}
}

// clientTLSConfiguration calculates the right certificates and requests to the clients.
func (p *Config) clientTLSConfiguration(conn net.Conn, originalConfig *tls.Config) (*tls.Config, error) {
	if mconn, ok := conn.(*markedconn.ProxiedConnection); ok {
		ip, port := mconn.GetOriginalDestination()
		portContext, err := p.registry.RetrieveExposedServiceContext(ip, port, "")
		if err != nil {
			return nil, fmt.Errorf("Unknown service: %s", err)
		}
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
		return originalConfig, nil
	}
	return nil, fmt.Errorf("Invalid connection")
}

// newBaseTLSConfig creates the new basic TLS configuration for the server.
func (p *Config) newBaseTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate:           p.GetCertificateFunc(),
		NextProtos:               []string{"h2"},
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
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
	if encrypted {
		config := p.newBaseTLSConfig()
		config.GetConfigForClient = func(helloMsg *tls.ClientHelloInfo) (*tls.Config, error) {
			return p.clientTLSConfiguration(helloMsg.Conn, config)
		}
		l = tls.NewListener(l, config)
	}

	reportStats := func(ctx context.Context) {
		if state := ctx.Value(statsContextKey); state != nil {
			if r, ok := state.(*connectionState); ok {
				r.stats.Action = policy.Reject
				r.stats.DropReason = collector.UnableToDial
				r.stats.PolicyID = "default"
				p.collector.CollectFlowEvent(r.stats)
			}
		}
	}

	networkDialerWithContext := func(ctx context.Context, network, _ string) (net.Conn, error) {
		raddr, ok := ctx.Value(http.LocalAddrContextKey).(*net.TCPAddr)
		if !ok {
			reportStats(ctx)
			return nil, fmt.Errorf("invalid destination address")
		}
		// TODO(windows): need to handle nativeData properly
		conn, err := markedconn.DialMarkedWithContext(ctx, "tcp", raddr.String(), nil, p.mark)
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
		// TODO(windows): need to handle nativeData properly
		conn, err := markedconn.DialMarkedWithContext(ctx, "tcp", raddr.String(), nil, p.mark)
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
		// TODO(windows): need to handle nativeData properly
		conn, err := markedconn.DialMarkedWithContext(ctx, "tcp", raddr.String(), nil, p.mark)
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
		// TODO(windows): need to handle nativeData properly
		conn, err := markedconn.DialMarkedWithContext(ctx, "tcp", raddr.String(), nil, p.mark)
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
		forward.BufferPool(NewPool()),
		forward.ErrorHandler(TriremeHTTPErrHandler{}),
	)
	if err != nil {
		return fmt.Errorf("Cannot initialize encrypted transport: %s", err)
	}

	p.fwd, err = forward.New(
		forward.RoundTripper(NewTriremeRoundTripper(transport)),
		forward.WebsocketTLSClientConfig(&tls.Config{InsecureSkipVerify: true}),
		forward.WebSocketNetDial(appDial),
		forward.BufferPool(NewPool()),
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
	defer p.Unlock()

	p.cert = cert
	p.ca = caPool
	p.secrets = s
	p.certPEM = certPEM
	p.keyPEM = keyPEM
	p.tlsClientConfig.RootCAs = caPool
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
			return p.cert, nil
		}
		return nil, fmt.Errorf("no cert available - cert is nil")
	}
}

func (p *Config) retrieveNetworkContext(originalIP *net.TCPAddr) (*serviceregistry.PortContext, error) {

	return p.registry.RetrieveExposedServiceContext(originalIP.IP, originalIP.Port, "")
}

func (p *Config) retrieveApplicationContext(address *net.TCPAddr) (*serviceregistry.ServiceContext, *urisearch.APICache, error) {

	sctx, serviceData, err := p.registry.RetrieveServiceDataByIDAndNetwork(p.puContext, address.IP, address.Port, "")
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to discover service data: %s", err)
	}
	return sctx, serviceData.APICache, nil
}

func (p *Config) processAppRequest(w http.ResponseWriter, r *http.Request) {

	zap.L().Debug("Processing Application Request", zap.String("URI", r.RequestURI), zap.String("Host", r.Host))

	originalDestination := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	sctx, apiCache, err := p.retrieveApplicationContext(originalDestination)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unknown service"), http.StatusBadGateway)
		zap.L().Error("Cannot identify application context", zap.Error(err))
		return
	}

	state := newAppConnectionState(p.puContext, apiCache.ID, sctx.PUContext, r, originalDestination)

	_, netaction, noNetAccesPolicy := sctx.PUContext.ApplicationACLPolicyFromAddr(originalDestination.IP, uint16(originalDestination.Port))
	state.stats.PolicyID = netaction.PolicyID
	if noNetAccesPolicy == nil && netaction.Action.Rejected() {
		http.Error(w, fmt.Sprintf("Unauthorized Service - Rejected Outgoing Request by Network Policies"), http.StatusNetworkAuthenticationRequired)
		p.collector.CollectFlowEvent(state.stats)
		return
	}

	// For external services we validate policy at the ingress. Note, that the
	// certificate distribution service is considered as external and must
	// be defined as external.
	if apiCache.External {
		// Get the corresponding scopes
		found, rule := apiCache.FindRule(r.Method, r.URL.Path)
		if !found {
			p.collector.CollectFlowEvent(state.stats)
			zap.L().Error("Unknown  or unauthorized service - no policy found", zap.Error(err))
			http.Error(w, fmt.Sprintf("Unknown or unauthorized service - no policy found"), http.StatusForbidden)
			return
		}
		// If it is a secrets request we process it and move on. No need to
		// validate policy.
		if p.isSecretsRequest(w, r, sctx) {
			zap.L().Debug("Processing certificate request", zap.String("URI", r.RequestURI))
			return
		}
		if !rule.Public {
			// Validate the policy based on the scopes of the PU.
			// TODO: Add user scopes
			if !apiCache.MatchClaims(rule.ClaimMatchingRules, append(sctx.PUContext.Identity().Tags, sctx.PUContext.Scopes()...)) {
				p.collector.CollectFlowEvent(state.stats)
				zap.L().Error("Unknown  or unauthorized service", zap.Error(err))
				http.Error(w, fmt.Sprintf("Unknown or unauthorized service - rejected by policy"), http.StatusForbidden)
				return
			}
		}
		state.stats.Action = policy.Accept | policy.Encrypt
		p.collector.CollectFlowEvent(state.stats)
	}

	token, err := servicetokens.CreateAndSign(
		p.server.Addr,
		sctx.PUContext.Identity().Tags,
		sctx.PUContext.Scopes(),
		sctx.PUContext.ManagementID(),
		defaultValidity,
		p.secrets.EncodingKey(),
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("Cannot handle request - cannot create token"), http.StatusForbidden)
		return
	}

	// Create the new target URL based on the Host parameter that we had.
	r.URL, err = url.ParseRequestURI("https://" + r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid destination host name"), http.StatusUnprocessableEntity)
		return
	}

	// Add the headers with the authorization parameters and public key. The other side
	// must validate our public key.
	r.Header.Add("X-APORETO-KEY", string(p.secrets.TransmittedKey()))
	r.Header.Add("X-APORETO-AUTH", token)

	contextWithStats := context.WithValue(r.Context(), statsContextKey, state)
	// Forward the request.
	p.fwdTLS.ServeHTTP(w, r.WithContext(contextWithStats))
}

func (p *Config) processNetRequest(w http.ResponseWriter, r *http.Request) {
	zap.L().Debug("Processing Network Request", zap.String("URI", r.RequestURI), zap.String("Host", r.Host))

	originalDestination := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)

	sourceAddress, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		zap.L().Error("Internal server error - cannot determine source address information", zap.Error(err))
		http.Error(w, fmt.Sprintf("Invalid network information"), http.StatusForbidden)
		return
	}

	// Retrieve the context and policy
	pctx, err := p.retrieveNetworkContext(originalDestination)
	if err != nil {
		zap.L().Error("Internal server error - cannot determine destination policy", zap.Error(err))
		http.Error(w, fmt.Sprintf("Unknown service"), http.StatusInternalServerError)
		return
	}

	// Create basic state information and associated record statistics.
	state := newNetworkConnectionState(p.puContext, pctx, r, sourceAddress, originalDestination)
	defer p.collector.CollectFlowEvent(state.stats)

	// Process callbacks without any other policy check.
	if strings.HasPrefix(r.RequestURI, TriremeOIDCCallbackURI) {
		pctx.Authorizer.Callback(w, r)
		state.stats.Action = policy.Accept
		return
	}

	// Check for network access rules that might require a drop.
	_, aclPolicy, noNetAccessPolicy := pctx.PUContext.NetworkACLPolicyFromAddr(sourceAddress.IP, uint16(originalDestination.Port))
	state.stats.PolicyID = aclPolicy.PolicyID
	state.stats.Source.ID = aclPolicy.ServiceID
	if noNetAccessPolicy == nil && aclPolicy.Action.Rejected() {
		http.Error(w, fmt.Sprintf("Access denied by network policy - Rejected"), http.StatusNetworkAuthenticationRequired)
		state.stats.DropReason = collector.PolicyDrop
		return
	}

	// Retrieve the headers with the key and auth parameters. If the parameters do not
	// exist, we will end up with empty values, but processing can continue. The authorizer
	// will validate if they are needed or not.
	token, key := processHeaders(r)

	// Calculate the user attributes. User attributes can be derived either from a
	// token or from a certificate. The authorizer library will parse them. We don't
	// care if there are no user credentials. It might be a request from a PU,
	// or it might be a request to a public interface. Only if the service mandates
	// user credentials, we get the redirect directive.
	userAttributes, redirect := userCredentials(pctx, r, p.collector, state)

	// Calculate the Aporeto PU claims by parsing the token if it exists. If the token
	// is mepty the DecodeAporetoClaims method will return no error.
	sourceID, aporetoClaims, err := pctx.Authorizer.DecodeAporetoClaims(token, key)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid Authorization Token: %s", err), http.StatusForbidden)
		state.stats.DropReason = collector.PolicyDrop
		return
	}
	if len(aporetoClaims) > 0 {
		state.stats.Source.ID = sourceID
		state.stats.Source.Type = collector.EnpointTypePU
	}

	// We need to verify network policy, before validating the API policy. If a network
	// policy has given us an accept because of IP address based ACLs we proceed anyway.
	// This is rather convoluted, but a user might choose to implement network
	// policies with ACLs only, and we have to cover this case.
	if noNetAccessPolicy != nil {
		if len(aporetoClaims) > 0 {
			_, netPolicyAction := pctx.PUContext.SearchRcvRules(policy.NewTagStoreFromSlice(aporetoClaims))
			state.stats.PolicyID = netPolicyAction.PolicyID
			if netPolicyAction.Action.Rejected() {
				http.Error(w, fmt.Sprintf("Access not authorized by network policy"), http.StatusNetworkAuthenticationRequired)
				state.stats.DropReason = collector.PolicyDrop
				return
			}
		} else {
			http.Error(w, fmt.Sprintf("Access denied by network policy - no policy found"), http.StatusNetworkAuthenticationRequired)
			return
		}
	} else {
		if aclPolicy.Action.Accepted() {
			aporetoClaims = append(aporetoClaims, aclPolicy.Labels...)
		}
	}

	// We can now validate the API authorization. This is the final step
	// before forwarding.
	allClaims := append(aporetoClaims, userAttributes...)
	accept, public := pctx.Authorizer.Check(r.Method, r.URL.Path, allClaims)
	if !accept {
		if !public {
			state.stats.DropReason = collector.PolicyDrop
			if state.stats.Source.Type != collector.EnpointTypePU {
				if redirect {
					w.Header().Add("Location", pctx.Authorizer.RedirectURI(r.URL.String()))
					http.Error(w, "No token presented or invalid token: Please authenticate first", http.StatusTemporaryRedirect)
					return
				} else if len(pctx.Service.UserRedirectOnAuthorizationFail) > 0 {
					w.Header().Add("Location", pctx.Service.UserRedirectOnAuthorizationFail+"?failure_message=authorization")
					http.Error(w, "Authorization failed", http.StatusTemporaryRedirect)
					return
				}
			}
			http.Error(w, fmt.Sprintf("Unauthorized Access to %s", r.URL), http.StatusUnauthorized)
			zap.L().Warn("No match found for the request or authorization Error",
				zap.String("Request", r.Method+" "+r.RequestURI),
				zap.Strings("User Attributes", userAttributes),
				zap.Strings("Aporeto Claims", aporetoClaims),
			)
			return
		}
	}

	// Select as http or https for communication with listening service.
	httpPrefix := "http://"
	if pctx.Service.PrivateTLSListener {
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
		state.stats.DropReason = collector.InvalidFormat
		http.Error(w, fmt.Sprintf("Invalid HTTP Host parameter: %s", err), http.StatusBadRequest)
		return
	}

	// Update the request headers with the user attributes as defined by the mappings
	pctx.Authorizer.UpdateRequestHeaders(r, userAttributes)

	// Update the statistics and forward the request. We always encrypt downstream
	state.stats.Action = policy.Accept | policy.Encrypt
	state.stats.Destination.IP = originalDestination.IP.String()
	state.stats.Destination.Port = uint16(originalDestination.Port)

	// Treat the remote proxy scenario where the destination IPs are in a remote
	// host. Check of network rules that allow this transfer and report the corresponding
	// flows.
	if _, ok := p.localIPs[originalDestination.IP.String()]; !ok {
		_, action, err := pctx.PUContext.ApplicationACLPolicyFromAddr(originalDestination.IP, uint16(originalDestination.Port))
		if err != nil || action.Action.Rejected() {
			defer p.collector.CollectFlowEvent(reportDownStream(state.stats, action))
			http.Error(w, fmt.Sprintf("Access denied by network policy to downstream IP: %s", originalDestination.IP.String()), http.StatusNetworkAuthenticationRequired)
			return
		}
		if action.Action.Accepted() {
			defer p.collector.CollectFlowEvent(reportDownStream(state.stats, action))
		}
	}
	contextWithStats := context.WithValue(r.Context(), statsContextKey, state)
	p.fwd.ServeHTTP(w, r.WithContext(contextWithStats))
	zap.L().Debug("Forwarding Request", zap.String("URI", r.RequestURI), zap.String("Host", r.Host))
}

func (p *Config) isSecretsRequest(w http.ResponseWriter, r *http.Request, sctx *serviceregistry.ServiceContext) bool {

	if r.Host != "169.254.254.1" {
		return false
	}

	switch r.RequestURI {
	case "/certificate":
		if _, err := w.Write([]byte(p.certPEM)); err != nil {
			zap.L().Error("Unable to write response")
		}
	case "/key":
		if _, err := w.Write([]byte(p.keyPEM)); err != nil {
			zap.L().Error("Unable to write response")
		}
	case "/health":
		plc := sctx.PU.Policy.ToPublicPolicy()
		plc.ServicesCertificate = ""
		plc.ServicesPrivateKey = ""
		data, err := json.Marshal(plc)
		if err != nil {
			data = []byte("Internal Server Error")
		}
		if _, err := w.Write(data); err != nil {
			zap.L().Error("Unable to write response to health API")
		}

	default:
		http.Error(w, fmt.Sprintf("Unknown"), http.StatusBadRequest)
	}

	return true
}

// userCredentials will find all the user credentials in the http request.
// TODO: In addition to looking at the headers, we need to look at the parameters
// in case authorization is provided there.
// It will return the userAttributes and a boolean instructing whether a redirect
// must be performed. If no user credentials are found, it will allow processing
// to proceed. It might be a
func userCredentials(pctx *serviceregistry.PortContext, r *http.Request, c collector.EventCollector, state *connectionState) ([]string, bool) {
	if r.TLS == nil {
		return []string{}, false
	}
	userCerts := r.TLS.PeerCertificates

	var userToken string
	authToken := r.Header.Get("Authorization")
	if len(authToken) < 7 {
		cookie, err := r.Cookie("X-APORETO-AUTH")
		if err == nil {
			userToken = cookie.Value
		}
	} else {
		userToken = strings.TrimPrefix(authToken, "Bearer ")
	}

	userAttributes, redirect, refreshedToken, err := pctx.Authorizer.DecodeUserClaims(pctx.Service.ID, userToken, userCerts, r)
	if len(userAttributes) > 0 {
		userRecord := &collector.UserRecord{
			Namespace: pctx.PUContext.ManagementNamespace(),
			Claims:    userAttributes}
		c.CollectUserEvent(userRecord)
		state.stats.Source.UserID = userRecord.ID
		state.stats.Source.Type = collector.EndpointTypeClaims
	}
	if err != nil && len(userAttributes) > 0 {
		zap.L().Warn("Partially failed to extract and decode user claims", zap.Error(err))
	} else if err != nil {
		zap.L().Error("Failed to decode user claims", zap.Error(err))
	}

	if refreshedToken != userToken {
		state.cookie = &http.Cookie{
			Name:     "X-APORETO-AUTH",
			Value:    refreshedToken,
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
		}
	}

	return userAttributes, redirect
}

func reportDownStream(record *collector.FlowRecord, action *policy.FlowPolicy) *collector.FlowRecord {
	return &collector.FlowRecord{
		ContextID: record.ContextID,
		Destination: &collector.EndPoint{
			URI:        record.Destination.URI,
			HTTPMethod: record.Destination.HTTPMethod,
			Type:       collector.EndPointTypeExternalIP,
			Port:       record.Destination.Port,
			IP:         record.Destination.IP,
			ID:         action.ServiceID,
		},
		Source: &collector.EndPoint{
			Type: record.Destination.Type,
			ID:   record.Destination.ID,
			IP:   "0.0.0.0",
		},
		Action:      action.Action,
		L4Protocol:  record.L4Protocol,
		ServiceType: record.ServiceType,
		ServiceID:   record.ServiceID,
		Tags:        record.Tags,
		PolicyID:    action.PolicyID,
		Count:       1,
	}
}

func processHeaders(r *http.Request) (string, string) {
	token := r.Header.Get("X-APORETO-AUTH")
	if token != "" {
		r.Header.Del("X-APORETO-AUTH")
	}
	key := r.Header.Get("X-APORETO-KEY")
	if key != "" {
		r.Header.Del("X-APORETO-KEY")
	}
	return token, key
}
