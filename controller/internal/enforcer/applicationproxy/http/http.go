package httpproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aporeto-inc/oxy/forward"
	"github.com/dgrijalva/jwt-go"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/connproc"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
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
		localIPs:         connproc.GetInterfaces(),
		registry:         registry,
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
		if portContext.Service.UserAuthorizationType == policy.UserAuthorizationMutualTLS {
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
		if statsRecord := ctx.Value(statsContextKey); statsRecord != nil {
			if r, ok := statsRecord.(*collector.FlowRecord); ok {
				r.Action = policy.Reject
				r.DropReason = collector.UnableToDial
				r.PolicyID = "default"
				p.collector.CollectFlowEvent(r)
			}
		}
	}

	networkDialerWithContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		raddr, err := net.ResolveTCPAddr(network, ctx.Value(http.LocalAddrContextKey).(*net.TCPAddr).String())
		if err != nil {
			reportStats(ctx)
			return nil, err
		}
		conn, err := markedconn.DialMarkedTCP("tcp", nil, raddr, p.mark)
		if err != nil {
			reportStats(ctx)
			return nil, fmt.Errorf("Failed to dial remote: %s", err)
		}
		return conn, nil
	}

	appDialerWithContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		raddr, err := net.ResolveTCPAddr(network, ctx.Value(http.LocalAddrContextKey).(*net.TCPAddr).String())
		if err != nil {
			reportStats(ctx)
			return nil, err
		}
		pctx, err := p.registry.RetrieveExposedServiceContext(raddr.IP, raddr.Port, "")
		if err != nil {
			return nil, err
		}
		raddr.Port = pctx.TargetPort
		conn, err := markedconn.DialMarkedTCP("tcp", nil, raddr, p.mark)
		if err != nil {
			reportStats(ctx)
			return nil, fmt.Errorf("Failed to dial remote: %s", err)
		}
		return conn, nil
	}

	// Create an encrypted downstream transport. We will mark the downstream connection
	// to let the iptables rule capture it.
	encryptedTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: p.ca,
		},
		DialContext:         networkDialerWithContext,
		MaxIdleConnsPerHost: 2000,
		MaxIdleConns:        2000,
	}

	// Create an unencrypted transport for talking to the application
	transport := &http.Transport{
		DialContext:         appDialerWithContext,
		MaxIdleConns:        2000,
		MaxIdleConnsPerHost: 2000,
	}

	netDial := func(network, addr string) (net.Conn, error) {
		raddr, err := net.ResolveTCPAddr(network, addr)
		if err != nil {
			return nil, fmt.Errorf("Cannot resolve address")
		}
		return markedconn.DialMarkedTCP(network, nil, raddr, p.mark)
	}

	// Create the proxies dowards the network and the application.
	var err error
	p.fwdTLS, err = forward.New(forward.RoundTripper(encryptedTransport),
		forward.WebsocketTLSClientConfig(&tls.Config{RootCAs: p.ca}),
		forward.WebSocketNetDial(netDial),
		forward.BufferPool(NewPool()),
	)
	if err != nil {
		return fmt.Errorf("Cannot initialize encrypted transport: %s", err)
	}

	p.fwd, err = forward.New(
		forward.RoundTripper(transport),
		forward.BufferPool(NewPool()),
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
	sctx, err := p.registry.RetrieveServiceByID(p.puContext)
	if err != nil {
		return nil, nil, fmt.Errorf("Unknown service: %s", err)
	}
	data := sctx.DependentServiceCache.Find(address.IP.To4(), address.Port, "", false)
	if data == nil {
		return nil, nil, fmt.Errorf("Failed to find API cache")
	}

	apiCache, ok := data.(*urisearch.APICache)
	if !ok {
		return nil, nil, fmt.Errorf("Internal error - wrong types")
	}
	return sctx, apiCache, nil
}

func (p *Config) processAppRequest(w http.ResponseWriter, r *http.Request) {

	zap.L().Debug("Processing Application Request", zap.String("URI", r.RequestURI), zap.String("Host", r.Host))

	originalDestination := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)

	sctx, apiCache, err := p.retrieveApplicationContext(originalDestination)
	if err != nil {
		zap.L().Error("Cannot identify application context", zap.Error(err))
		return
	}

	record := &collector.FlowRecord{
		ContextID: p.puContext,
		Destination: &collector.EndPoint{
			URI:        r.Method + " " + r.RequestURI,
			HTTPMethod: r.Method,
			Type:       collector.EndPointTypeExternalIP,
			Port:       uint16(originalDestination.Port),
			IP:         originalDestination.IP.String(),
			ID:         collector.DefaultEndPoint,
		},
		Source: &collector.EndPoint{
			Type: collector.EnpointTypePU,
			ID:   sctx.PUContext.ManagementID(),
			IP:   "0.0.0.0/0",
		},
		Action:      policy.Reject,
		L4Protocol:  packet.IPProtocolTCP,
		ServiceType: policy.ServiceHTTP,
		ServiceID:   apiCache.ID,
		Tags:        sctx.PUContext.Annotations(),
		Count:       1,
	}

	_, netaction, noNetAccesPolicy := sctx.PUContext.ApplicationACLPolicyFromAddr(originalDestination.IP.To4(), uint16(originalDestination.Port))
	if noNetAccesPolicy == nil && netaction.Action.Rejected() {
		http.Error(w, fmt.Sprintf("Unauthorized Service - Rejected Outgoing Request by Network Policies"), http.StatusNetworkAuthenticationRequired)
		record.PolicyID = netaction.PolicyID
		record.DropReason = collector.PolicyDrop
		p.collector.CollectFlowEvent(record)
		return
	}

	// For external services we validate policy at the ingress. Note, that the
	// certificate distribution service is considered as external and must
	// be defined as external.
	if apiCache.External {
		// Get the corresponding scopes
		found, rule := apiCache.FindRule(r.Method, r.URL.Path)
		if !found {
			zap.L().Error("Uknown  or unauthorized service - no policy found", zap.Error(err))
			http.Error(w, fmt.Sprintf("Unknown or unauthorized service - no policy found"), http.StatusForbidden)
			return
		}
		// If it is a secrets request we process it and move on. No need to
		// validate policy.
		if p.isSecretsRequest(w, r) {
			zap.L().Debug("Processing certificate request", zap.String("URI", r.RequestURI))
			return
		}
		if !rule.Public {
			// Validate the policy based on the scopes of the PU.
			// TODO: Add user scopes
			if err = p.verifyPolicy(rule.Scopes, sctx.PUContext.Identity().Tags, sctx.PUContext.Scopes(), []string{}); err != nil {
				zap.L().Error("Uknown  or unauthorized service", zap.Error(err))
				http.Error(w, fmt.Sprintf("Unknown or unauthorized service - rejected by policy"), http.StatusForbidden)
				return
			}
			// All checks have passed. We can accept the request, log it, and create the
			// right tokens. If it is not an external service, we do not log at the transmit side.
			record.Action = policy.Encrypt
		}
		record.Action = record.Action | policy.Accept
		p.collector.CollectFlowEvent(record)
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

	contextWithStats := context.WithValue(r.Context(), statsContextKey, record)
	// Forward the request.
	p.fwdTLS.ServeHTTP(w, r.WithContext(contextWithStats))
}

func (p *Config) processNetRequest(w http.ResponseWriter, r *http.Request) {
	zap.L().Debug("Processing Network Request", zap.String("URI", r.RequestURI), zap.String("Host", r.Host))
	originalDestination := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)

	sourceAddress, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid network information"), http.StatusForbidden)
		return
	}

	record := &collector.FlowRecord{
		ContextID: p.puContext,
		Destination: &collector.EndPoint{
			URI:        r.Method + " " + r.RequestURI,
			HTTPMethod: r.Method,
			Type:       collector.EnpointTypePU,
			IP:         originalDestination.IP.String(),
			Port:       uint16(originalDestination.Port),
		},
		Source: &collector.EndPoint{
			Type: collector.EndPointTypeExternalIP,
			IP:   sourceAddress.IP.String(),
			ID:   collector.DefaultEndPoint,
		},
		Action:      policy.Reject,
		L4Protocol:  packet.IPProtocolTCP,
		ServiceType: policy.ServiceHTTP,
		PolicyID:    "default",
		Count:       1,
	}

	defer p.collector.CollectFlowEvent(record)

	// Retrieve the context and policy
	pctx, err := p.retrieveNetworkContext(originalDestination)
	if err != nil {
		http.Error(w, fmt.Sprintf("Uknown service"), http.StatusInternalServerError)
		record.DropReason = collector.PolicyDrop
		p.collector.CollectFlowEvent(record)
		return
	}
	record.ServiceID = pctx.Service.ID
	record.Tags = pctx.PUContext.Annotations()
	record.Destination.ID = pctx.PUContext.ManagementID()

	if strings.HasPrefix(r.RequestURI, "/aporeto/oidc/callback") {
		pctx.Authorizer.Callback(w, r)
		record.Action = policy.Accept
		return
	}

	// Check for network access rules that might require a drop.
	_, aclPolicy, noNetAccessPolicy := pctx.PUContext.NetworkACLPolicyFromAddr(sourceAddress.IP.To4(), uint16(originalDestination.Port))
	record.PolicyID = aclPolicy.PolicyID
	record.Source.ID = aclPolicy.ServiceID
	if noNetAccessPolicy == nil && aclPolicy.Action.Rejected() {
		http.Error(w, fmt.Sprintf("Access denied by network policy - Rejected"), http.StatusNetworkAuthenticationRequired)
		record.DropReason = collector.PolicyDrop
		return
	}

	// Retrieve the headers with the key and auth parameters. If the parameters do not
	// exist, we will end up with empty values, but processing can continue. The authorizer
	// will validate if they are needed or not.
	token := r.Header.Get("X-APORETO-AUTH")
	if token != "" {
		r.Header.Del("X-APORETO-AUTH")
	}
	key := r.Header.Get("X-APORETO-KEY")
	if key != "" {
		r.Header.Del("X-APORETO-LEN")
	}

	// Calculate the user attributes. User attributes can be derived either from a
	// token or from a certificate. The authorizer library will parse them.
	userToken, userCerts := userCredentials(r)
	userAttributes, redirect, err := pctx.Authorizer.DecodeUserClaims(pctx.Service.ID, userToken, userCerts, r)
	if err == nil && len(userAttributes) > 0 {
		userRecord := &collector.UserRecord{Claims: userAttributes}
		p.collector.CollectUserEvent(userRecord)
		record.Source.UserID = userRecord.ID
		record.Source.Type = collector.EndpointTypeClaims
	}

	// Calculate the Aporeto PU claims by parsing the token if it exists.
	sourceID, aporetoClaims := pctx.Authorizer.DecodeAporetoClaims(token, key)
	if len(aporetoClaims) > 0 {
		record.Source.ID = sourceID
		record.Source.Type = collector.EnpointTypePU
	}

	// We need to verify network policy, before validating the API policy. If a network
	// policy has given us an accept because of IP address based ACLs we proceed anyway.
	// This is rather convoluted, but a user might choose to implement network
	// policies with ACLs only, and we have to cover this case.
	if noNetAccessPolicy != nil {
		if len(aporetoClaims) > 0 {
			_, netPolicyAction := pctx.PUContext.SearchRcvRules(policy.NewTagStoreFromSlice(aporetoClaims))
			record.PolicyID = netPolicyAction.PolicyID
			if netPolicyAction.Action.Rejected() {
				http.Error(w, fmt.Sprintf("Access not authorized by network policy"), http.StatusNetworkAuthenticationRequired)
				record.DropReason = collector.PolicyDrop
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
			record.DropReason = collector.PolicyDrop
			if record.Source.Type != collector.EnpointTypePU {
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

	// Create the target URI. Websocket Gorilla proxy takes it from the URL. For normal
	// connections we don't want that.
	if forward.IsWebsocketRequest(r) {
		r.URL, err = url.ParseRequestURI("http://" + originalDestination.String())
	} else {
		r.URL, err = url.ParseRequestURI("http://" + r.Host)
	}

	if err != nil {
		record.DropReason = collector.InvalidFormat
		http.Error(w, fmt.Sprintf("Invalid HTTP Host parameter: %s", err), http.StatusBadRequest)
		return
	}

	// Update the request headers with the user attributes as defined by the mappings
	pctx.Authorizer.UpdateRequestHeaders(r, userAttributes)

	// Update the statistics and forward the request. We always encrypt downstream
	record.Action = policy.Accept | policy.Encrypt
	record.Destination.IP = originalDestination.IP.String()
	record.Destination.Port = uint16(originalDestination.Port)

	// Treat the remote proxy scenario where the destination IPs are in a remote
	// host. Check of network rules that allow this transfer and report the corresponding
	// flows.
	if _, ok := p.localIPs[originalDestination.IP.String()]; !ok {
		_, action, err := pctx.PUContext.ApplicationACLPolicyFromAddr(originalDestination.IP.To4(), uint16(originalDestination.Port))
		if err != nil || action.Action.Rejected() {
			defer p.collector.CollectFlowEvent(reportDownStream(record, action))
			http.Error(w, fmt.Sprintf("Access to downstream denied by network policy"), http.StatusNetworkAuthenticationRequired)
			return
		}
		if action.Action.Accepted() {
			defer p.collector.CollectFlowEvent(reportDownStream(record, action))
		}
	}
	contextWithStats := context.WithValue(r.Context(), statsContextKey, record)
	p.fwd.ServeHTTP(w, r.WithContext(contextWithStats))
	zap.L().Debug("Forwarding Request", zap.String("URI", r.RequestURI), zap.String("Host", r.Host))
}

func (p *Config) verifyPolicy(apitags []string, profile, scopes []string, userAttributes []string) error {

	// TODO: Silly implementation. We can do a better lookup here.
	for _, a := range apitags {
		for _, user := range userAttributes {
			if user == a {
				return nil
			}
		}
		for _, c := range profile {
			if a == c {
				return nil
			}
		}
		for _, c := range scopes {
			if a == c {
				return nil
			}
		}
	}

	zap.L().Warn("No match found in API token",
		zap.Strings("User Attributes", userAttributes),
		zap.Strings("API Policy", apitags),
		zap.Strings("PU Claims", profile),
		zap.Strings("PU Scopes", scopes),
	)
	return fmt.Errorf("No matching authorization policy")
}

func (p *Config) isSecretsRequest(w http.ResponseWriter, r *http.Request) bool {

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
	default:
		http.Error(w, fmt.Sprintf("Uknown"), http.StatusBadRequest)
	}

	return true
}

// userCredentials will find all the user credentials in the http request.
// TODO: In addition to looking at the headers, we need to look at the parameters
// in case authorization is provided there.
func userCredentials(r *http.Request) (string, []*x509.Certificate) {
	if r.TLS == nil {
		return "", nil
	}

	certs := r.TLS.PeerCertificates

	authorization := r.Header.Get("Authorization")
	if len(authorization) < 7 {
		cookie, err := r.Cookie("X-APORETO-AUTH")
		if err == nil {
			return cookie.Value, certs
		}
		return "", certs
	}

	authorization = strings.TrimPrefix(authorization, "Bearer ")

	return authorization, certs
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
