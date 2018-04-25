package httpproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/packet"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/pucontext"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/secrets"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/urisearch"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
	"github.com/dgrijalva/jwt-go"
	"github.com/vulcand/oxy/forward"
	"go.uber.org/zap"
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
	cert              *tls.Certificate
	ca                *x509.CertPool
	keyPEM            string
	certPEM           string
	secrets           secrets.Secrets
	tokenaccessor     tokenaccessor.TokenAccessor
	collector         collector.EventCollector
	puContext         string
	puFromIDCache     cache.DataStore
	exposedAPICache   cache.DataStore
	dependentAPICache cache.DataStore
	jwtCache          cache.DataStore
	applicationProxy  bool
	mark              int
	server            *http.Server
	fwd               *forward.Forwarder
	fwdTLS            *forward.Forwarder
	sync.RWMutex
}

// NewHTTPProxy creates a new instance of proxy reate a new instance of Proxy
func NewHTTPProxy(
	tp tokenaccessor.TokenAccessor,
	c collector.EventCollector,
	puContext string,
	puFromIDCache cache.DataStore,
	caPool *x509.CertPool,
	exposedAPICache cache.DataStore,
	dependentAPICache cache.DataStore,
	jwtCache cache.DataStore,
	applicationProxy bool,
	mark int,
	secrets secrets.Secrets,
) *Config {

	return &Config{
		collector:         c,
		tokenaccessor:     tp,
		puFromIDCache:     puFromIDCache,
		puContext:         puContext,
		ca:                caPool,
		exposedAPICache:   exposedAPICache,
		dependentAPICache: dependentAPICache,
		applicationProxy:  applicationProxy,
		jwtCache:          jwtCache,
		mark:              mark,
		secrets:           secrets,
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
			ClientAuth:     tls.RequestClientCert,
		}
		l = tls.NewListener(l, config)
	}

	// Create an encrypted downstream transport
	encryptedTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: p.ca,
		},

		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raddr, err := net.ResolveTCPAddr(network, addr)
			if err != nil {
				return nil, err
			}
			conn, err := markedconn.DialMarkedTCP("tcp", nil, raddr, p.mark)
			if err != nil {
				return nil, err
			}

			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         getServerName(addr),
				RootCAs:            p.ca,
				InsecureSkipVerify: false,
			})
			return tlsConn, nil
		},
	}

	// Create an unencrypted transport for talking to the application
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raddr, err := net.ResolveTCPAddr(network, addr)
			if err != nil {
				return nil, err
			}
			conn, err := markedconn.DialMarkedTCP("tcp", nil, raddr, p.mark)
			if err != nil {
				return nil, fmt.Errorf("Failed to dial remote: %s", err)
			}
			return conn, nil
		},
	}

	var err error
	p.fwdTLS, err = forward.New(forward.RoundTripper(encryptedTransport))
	if err != nil {
		return fmt.Errorf("Cannot initialize encrypted transport: %s", err)
	}

	p.fwd, err = forward.New(forward.RoundTripper(transport))
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
		return nil, fmt.Errorf("no cert available")
	}
}

func (p *Config) retrieveContextAndPolicy(c cache.DataStore, w http.ResponseWriter, r *http.Request) (*pucontext.PUContext, *urisearch.APICache, error) {
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
	data, err := c.Get(p.puContext)
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

	puContext, apiCache, err := p.retrieveContextAndPolicy(p.dependentAPICache, w, r)
	if err != nil {
		return
	}

	// For external services we validate policy at the ingress. Note that the
	// certificate distribution service is considered as external and must
	// be defined as external.
	if apiCache.External {
		_, _port, perr := originalServicePort(w, r)
		if perr != nil {
			return
		}
		record := &collector.FlowRecord{
			ContextID: p.puContext,
			Destination: &collector.EndPoint{
				URI:        r.RequestURI,
				HTTPMethod: r.Method,
				Type:       collector.EndPointTypeExteranlIPAddress,
				Port:       _port,
				IP:         r.Host,
				ID:         collector.DefaultEndPoint,
			},
			Source: &collector.EndPoint{
				Type: collector.EnpointTypePU,
				ID:   puContext.ManagementID(),
			},
			Action:      policy.Reject,
			L4Protocol:  packet.IPProtocolTCP,
			ServiceType: policy.ServiceHTTP,
			ServiceID:   apiCache.ID,
			Tags:        puContext.Annotations(),
		}
		defer p.collector.CollectFlowEvent(record)

		// Get the corresponding scopes
		found, t := apiCache.Find(r.Method, r.RequestURI)
		if !found {
			zap.L().Error("Uknown  or unauthorized service - no policy found", zap.Error(err))
			http.Error(w, fmt.Sprintf("Unknown or unauthorized service - no policy found"), http.StatusForbidden)
			return
		}

		rule, ok := t.(*policy.HTTPRule)
		if !ok {
			zap.L().Error("Internal error - wrong rule", zap.Error(err))
			http.Error(w, fmt.Sprintf("Internal server error"), http.StatusInternalServerError)
			return
		}
		if !rule.Public {
			// If it is a secrets request we process it and move on. No need to
			// validate policy.
			if p.isSecretsRequest(w, r) {
				zap.L().Debug("Processing certificate request", zap.String("URI", r.RequestURI))
				return
			}

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
	}

	// Generate the client identity
	token, err := p.createClientToken(puContext)
	if err != nil {
		http.Error(w, fmt.Sprintf("Cannot handle request - cannot create token"), http.StatusForbidden)
		return
	}

	// Create the new target URL based on the Host parameter that we had.
	r.URL, err = url.ParseRequestURI("http://" + r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid destination host name"), http.StatusUnprocessableEntity)
		return
	}

	// Add the headers with the authorization parameters and public key. The other side
	// must validate our public key.
	r.Header.Add("X-APORETO-KEY", string(p.secrets.TransmittedKey()))
	r.Header.Add("X-APORETO-AUTH", token)

	// Forward the request.
	p.fwdTLS.ServeHTTP(w, r)
}

func (p *Config) processNetRequest(w http.ResponseWriter, r *http.Request) {

	zap.L().Debug("Processing Network Request", zap.String("URI", r.RequestURI), zap.String("Host", r.Host))

	record := &collector.FlowRecord{
		ContextID: p.puContext,
		Destination: &collector.EndPoint{
			URI:        r.RequestURI,
			HTTPMethod: r.Method,
			Type:       collector.EnpointTypePU,
		},
		Source: &collector.EndPoint{
			Type: collector.EndpointTypeClaim,
			ID:   collector.AnyClaimSource,
		},
		Action:      policy.Reject,
		L4Protocol:  packet.IPProtocolTCP,
		ServiceType: policy.ServiceHTTP,
	}
	defer p.collector.CollectFlowEvent(record)

	// Retrieve the context and policy
	puContext, apiCache, err := p.retrieveContextAndPolicy(p.exposedAPICache, w, r)
	if err != nil {
		return
	}
	record.ServiceID = apiCache.ID

	// Find the original port from the URL
	port, _port, err := originalServicePort(w, r)
	if err != nil {
		return
	}

	record.Destination.Port = uint16(_port)
	record.Tags = puContext.Annotations()
	record.Destination.ID = puContext.ManagementID()

	// Retrieve the headers with the key and auth parameters.
	token := r.Header.Get("X-APORETO-AUTH")
	if token != "" {
		r.Header.Del("X-APORETO-AUTH")
	}

	key := r.Header.Get("X-APORETO-KEY")
	if key != "" {
		r.Header.Del("X-APORETO-LEN")
	}

	// Process the Auth header for any JWT context.
	jwtcache, err := p.jwtCache.Get(p.puContext)
	if err != nil {
		zap.L().Warn("No JWT cache found for this pu", zap.Error(err))
	}

	jwtCert, ok := jwtcache.(map[string]*x509.Certificate)[port]
	if !ok {
		zap.L().Warn("No JWT found for this port", zap.String("port", port))
	}

	// Look in the cache for the method and request URI for the associated scopes
	// and policies.
	found, t := apiCache.Find(r.Method, r.RequestURI)
	if !found {
		http.Error(w, fmt.Sprintf("Unknown or unauthorized service"), http.StatusForbidden)
		return
	}

	rule, ok := t.(*policy.HTTPRule)
	if !ok {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !rule.Public {
		// Calculate the user attributes and claims.
		userAttributes := parseUserAttributes(r, jwtCert)
		if len(userAttributes) > 0 {
			userRecord := &collector.UserRecord{Claims: userAttributes}
			p.collector.CollectUserEvent(userRecord)
			record.Source.UserID = userRecord.ID
		}

		var claims *JWTClaims
		claims, err = p.parseClientToken(key, token)
		if err != nil && len(userAttributes) == 0 {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		record.Source.ID = claims.SourceID

		// Validate the policy and drop the request if there is no authorization.
		if err = p.verifyPolicy(rule.Scopes, claims.Profile, claims.Scopes, userAttributes); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
	}

	// Create the target URI and forward the request.

	r.URL, err = url.ParseRequestURI("http://" + r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr).String())
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid HTTP Host parameter: %s", err), http.StatusBadRequest)
		return
	}

	record.Action = policy.Accept | policy.Encrypt
	p.fwd.ServeHTTP(w, r)
}

func (p *Config) createClientToken(puContext *pucontext.PUContext) (string, error) {

	claims := &JWTClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    p.server.Addr,
			ExpiresAt: time.Now().Add(10 * time.Second).Unix(),
		},
		Profile:  puContext.Identity().Tags,
		Scopes:   puContext.Scopes(),
		SourceID: puContext.ManagementID(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(p.secrets.EncodingKey())
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

func (p *Config) parseClientToken(txtKey string, token string) (*JWTClaims, error) {
	key, err := p.secrets.VerifyPublicKey([]byte(txtKey))
	if err != nil {
		return &JWTClaims{}, fmt.Errorf("Invalid Service Token")
	}

	claims := &JWTClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		ekey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("Invalid key")
		}
		return ekey, nil
	})
	if err != nil {
		return claims, fmt.Errorf("Error parsing token: %s", err)
	}
	return claims, nil
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

func getServerName(addr string) string {
	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		return parts[0]
	}
	return addr
}

func parseUserAttributes(r *http.Request, cert *x509.Certificate) []string {
	attributes := []string{}
	for _, cert := range r.TLS.PeerCertificates {
		attributes = append(attributes, "user="+cert.Subject.CommonName)
		for _, email := range cert.EmailAddresses {
			attributes = append(attributes, "email="+email)
		}
	}

	authorization := r.Header.Get("Authorization")
	if len(authorization) < 7 {
		return attributes
	}

	authorization = strings.TrimPrefix(authorization, "Bearer ")
	if len(authorization) == 0 {
		return attributes
	}

	// Use a generic claims map. This allows us to customize the user attributes
	// by providing the right scopes in the API policy.
	claims := &jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(authorization, claims, func(token *jwt.Token) (interface{}, error) {
		if cert == nil {
			return nil, fmt.Errorf("Nil certificate - ignore")
		}
		switch token.Method {
		case token.Method.(*jwt.SigningMethodECDSA):
			if rcert, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
				return rcert, nil
			}
		case token.Method.(*jwt.SigningMethodRSA):
			if rcert, ok := cert.PublicKey.(*rsa.PublicKey); ok {
				return rcert, nil
			}
		default:
			return nil, fmt.Errorf("Unknown signing method")
		}
		return nil, fmt.Errorf("Signing method does not match certificate")
	})

	// We can't decode it. Just ignore the user attributes at this point.
	if err != nil || token == nil {
		zap.L().Warn("Identified toke, but it is invalid", zap.Error(err))
		return attributes
	}

	if !token.Valid {
		return attributes
	}

	for k, v := range *claims {
		if slice, ok := v.([]string); ok {
			for _, data := range slice {
				attributes = append(attributes, k+"="+data)
			}
		}
		if attr, ok := v.(string); ok {
			attributes = append(attributes, k+"="+attr)
		}
		if kv, ok := v.(map[string]interface{}); ok {
			for key, value := range kv {
				if attr, ok := value.(string); ok {
					attributes = append(attributes, k+":"+key+"="+attr)
				}
			}
		}
	}

	return attributes
}

func originalServicePort(w http.ResponseWriter, r *http.Request) (string, uint16, error) {
	var err error
	port := "80"
	if strings.Contains(r.Host, ":") {
		_, port, err = net.SplitHostPort(r.Host)
		if err != nil {
			zap.L().Error("Invalid HTTP port parameter", zap.Error(err))
			http.Error(w, fmt.Sprintf("Invalid HTTP port parameter: %s", err), http.StatusUnprocessableEntity)
			return "", 0, err
		}
	}
	_port, _ := strconv.Atoi(port)
	return port, uint16(_port), nil
}
