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
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/trireme-lib/controller/pkg/auth"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/servicetokens"
	"go.aporeto.io/trireme-lib/controller/pkg/urisearch"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
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
	cert               *tls.Certificate
	ca                 *x509.CertPool
	keyPEM             string
	certPEM            string
	secrets            secrets.Secrets
	verifier           *servicetokens.Verifier
	collector          collector.EventCollector
	puContext          string
	puFromIDCache      cache.DataStore
	authProcessorCache cache.DataStore
	serviceMapCache    cache.DataStore
	dependentAPICache  cache.DataStore
	jwtCache           cache.DataStore
	applicationProxy   bool
	mark               int
	server             *http.Server
	fwd                *forward.Forwarder
	fwdTLS             *forward.Forwarder
	sync.RWMutex
}

// NewHTTPProxy creates a new instance of proxy reate a new instance of Proxy
func NewHTTPProxy(
	c collector.EventCollector,
	puContext string,
	puFromIDCache cache.DataStore,
	caPool *x509.CertPool,
	serviceMap cache.DataStore,
	authProcessorCache cache.DataStore,
	dependentAPICache cache.DataStore,
	applicationProxy bool,
	mark int,
	secrets secrets.Secrets,
) *Config {

	return &Config{
		collector:          c,
		puFromIDCache:      puFromIDCache,
		puContext:          puContext,
		ca:                 caPool,
		authProcessorCache: authProcessorCache,
		serviceMapCache:    serviceMap,
		dependentAPICache:  dependentAPICache,
		applicationProxy:   applicationProxy,
		mark:               mark,
		secrets:            secrets,
		verifier:           servicetokens.NewVerifier(secrets, nil),
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
		config := &tls.Config{
			GetCertificate: p.GetCertificateFunc(),
			ClientAuth:     tls.RequestClientCert,
			NextProtos:     []string{"h2"},
			CipherSuites:   []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
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

	dialerWithContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
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

	// Create an encrypted downstream transport. We will mark the downstream connection
	// to let the iptables rule capture it.
	encryptedTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: p.ca,
		},
		DialContext:         dialerWithContext,
		MaxIdleConnsPerHost: 2000,
		MaxIdleConns:        2000,
	}

	// Create an unencrypted transport for talking to the application
	transport := &http.Transport{
		DialContext:         dialerWithContext,
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
		if p.cert != nil {
			return p.cert, nil
		}
		return nil, fmt.Errorf("no cert available - cert is nil")
	}
}

func (p *Config) retrieveNetworkContext(w http.ResponseWriter, r *http.Request) (*pucontext.PUContext, *auth.Processor, string, error) {
	pu, err := p.puFromIDCache.Get(p.puContext)
	if err != nil {
		zap.L().Error("Cannot find policy, dropping request")
		http.Error(w, fmt.Sprintf("Cannot handle request: %s", err), http.StatusInternalServerError)
		return nil, nil, "", err
	}
	puContext := pu.(*pucontext.PUContext)

	data, err := p.serviceMapCache.Get(p.puContext)
	if err != nil {
		http.Error(w, fmt.Sprintf("Cannot handle request - unknown context: %s", p.puContext), http.StatusForbidden)
		return nil, nil, "", err
	}

	serviceID, ok := data.(map[string]string)[appendDefaultPort(r.Host)]
	if !ok {
		http.Error(w, fmt.Sprintf("Cannot handle request - unknown destination %s", r.Host), http.StatusForbidden)
		return nil, nil, "", fmt.Errorf("Cannot handle request - unknown destination")
	}

	authorizer, err := p.authProcessorCache.Get(p.puContext)
	if err != nil {
		http.Error(w, fmt.Sprintf("Cannot handle request - unknown authorization %s %s", p.puContext, r.Host), http.StatusForbidden)
		return nil, nil, "", fmt.Errorf("Cannot handle request - unknown authorization: %s %s", p.puContext, r.Host)
	}

	return puContext, authorizer.(*auth.Processor), serviceID, nil
}

func (p *Config) retrieveApplicationContext(w http.ResponseWriter, r *http.Request) (*pucontext.PUContext, *urisearch.APICache, error) {
	pu, err := p.puFromIDCache.Get(p.puContext)
	if err != nil {
		zap.L().Error("Cannot find policy, dropping request")
		http.Error(w, fmt.Sprintf("Cannot handle request: %s", err), http.StatusInternalServerError)
		return nil, nil, err
	}
	puContext := pu.(*pucontext.PUContext)

	// Find the right API cache for this context and service. This is done in two steps.
	// First lookup is to find the PU context. Second lookup is to find the cache based on
	// the service.
	data, err := p.dependentAPICache.Get(p.puContext)
	if err != nil {
		http.Error(w, fmt.Sprintf("Cannot handle request - unknown context: %s", p.puContext), http.StatusForbidden)
		return nil, nil, err
	}

	apiCache, ok := data.(map[string]*urisearch.APICache)[appendDefaultPort(r.Host)]
	if !ok {
		http.Error(w, fmt.Sprintf("Cannot handle request - unknown destination %s", r.Host), http.StatusForbidden)
		return nil, nil, fmt.Errorf("Cannot handle request - unknown destination")
	}

	return puContext, apiCache, nil
}

func (p *Config) processAppRequest(w http.ResponseWriter, r *http.Request) {
	zap.L().Debug("Processing Application Request", zap.String("URI", r.RequestURI), zap.String("Host", r.Host))

	puContext, apiCache, err := p.retrieveApplicationContext(w, r)
	if err != nil {
		return
	}

	originalDestination := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)

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
			ID:   puContext.ManagementID(),
			IP:   "0.0.0.0/0",
		},
		Action:      policy.Reject,
		L4Protocol:  packet.IPProtocolTCP,
		ServiceType: policy.ServiceHTTP,
		ServiceID:   apiCache.ID,
		Tags:        puContext.Annotations(),
	}

	_, netaction, noNetAccesPolicy := puContext.ApplicationACLPolicyFromAddr(originalDestination.IP.To4(), uint16(originalDestination.Port))
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
			if err = p.verifyPolicy(rule.Scopes, puContext.Identity().Tags, puContext.Scopes(), []string{}); err != nil {
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
		puContext.Identity().Tags,
		puContext.Scopes(),
		puContext.ManagementID(),
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
	}

	defer p.collector.CollectFlowEvent(record)

	// Retrieve the context and policy
	puContext, authorizer, serviceID, err := p.retrieveNetworkContext(w, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Uknown service"), http.StatusInternalServerError)
		record.DropReason = collector.PolicyDrop
		return
	}
	record.ServiceID = serviceID
	record.Tags = puContext.Annotations()
	record.Destination.ID = puContext.ManagementID()

	if strings.HasPrefix(r.RequestURI, "/aporeto/authorization-code/callback") {
		authorizer.Callback(serviceID, w, r)
		return
	}

	// Check for network access rules that might require a drop.
	_, aclPolicy, noNetAccessPolicy := puContext.NetworkACLPolicyFromAddr(sourceAddress.IP.To4(), uint16(originalDestination.Port))
	record.PolicyID = aclPolicy.PolicyID
	record.Source.ID = aclPolicy.ServiceID
	if noNetAccessPolicy == nil && aclPolicy.Action.Rejected() {
		http.Error(w, fmt.Sprintf("Access denied by network policy"), http.StatusNetworkAuthenticationRequired)
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
	userAttributes, redirect, err := authorizer.DecodeUserClaims(serviceID, userToken, userCerts, r)
	if err == nil && len(userAttributes) > 0 && !redirect {
		userRecord := &collector.UserRecord{Claims: userAttributes}
		p.collector.CollectUserEvent(userRecord)
		record.Source.UserID = userRecord.ID
		record.Source.ID = userRecord.ID
		record.Source.Type = collector.EndpointTypeClaims
	}

	// Calculate the Aporeto PU claims by parsing the token if it exists.
	sourceID, aporetoClaims := authorizer.DecodeAporetoClaims(serviceID, token, key)
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
			_, netPolicyAction := puContext.SearchRcvRules(policy.NewTagStoreFromSlice(aporetoClaims))
			record.PolicyID = netPolicyAction.PolicyID
			if netPolicyAction.Action.Rejected() {
				http.Error(w, fmt.Sprintf("Access not authorized by network policy"), http.StatusNetworkAuthenticationRequired)
				record.DropReason = collector.PolicyDrop
				return
			}
		} else {
			http.Error(w, fmt.Sprintf("Access denied by network policy"), http.StatusNetworkAuthenticationRequired)
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
	accept, public := authorizer.Check(serviceID, r.Method, r.URL.Path, allClaims)
	if !accept {
		if !public {
			if redirect && len(aporetoClaims) == 0 {
				w.Header().Add("Location", authorizer.RedirectURI(serviceID, r.URL.String()))
				http.Error(w, "No token presented or invalid token: Please authenticate first", http.StatusTemporaryRedirect)
				return
			}
			http.Error(w, fmt.Sprintf("Unauthorized Access to %s", r.URL), http.StatusUnauthorized)
			record.DropReason = collector.PolicyDrop
			zap.L().Warn("No match found for the request or authorization Error",
				zap.String("Request", r.Method+" "+r.RequestURI),
				zap.Strings("User Attributes", userAttributes),
				zap.Strings("Aporeto Claims", aporetoClaims),
			)
			return
		}
	}

	// Create the target URI and forward the request.
	r.URL, err = url.ParseRequestURI("http://" + r.Host)
	if err != nil {
		record.DropReason = collector.InvalidFormat
		http.Error(w, fmt.Sprintf("Invalid HTTP Host parameter: %s", err), http.StatusBadRequest)
		return
	}

	// Update the request headers with the user attributes as defined by the mappings
	authorizer.UpdateRequestHeaders(serviceID, r, userAttributes)

	// Update the statistics and forward the request. We always encrypt downstream
	record.Action = policy.Accept | policy.Encrypt
	record.Destination.IP = originalDestination.IP.String()
	record.Destination.Port = uint16(originalDestination.Port)

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

func appendDefaultPort(address string) string {
	if !strings.Contains(address, ":") {
		return address + ":80"
	}
	return address
}

// userCredentials will find all the user credentials in the http request.
// TODO: In addition to looking at the headers, we need to look at the parameters
// in case authorization is provided there.
func userCredentials(r *http.Request) (string, []*x509.Certificate) {

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
