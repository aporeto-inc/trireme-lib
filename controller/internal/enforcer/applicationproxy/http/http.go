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
	"github.com/aporeto-inc/trireme-lib/controller/pkg/pucontext"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/secrets"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/urisearch"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
	"go.uber.org/zap"

	"github.com/dgrijalva/jwt-go"
	"github.com/vulcand/oxy/forward"
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
		return
	}

	if p.isSecretsRequest(w, r) {
		return
	}

	r.URL, err = url.ParseRequestURI("http://" + r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid host name: %s ", err), http.StatusUnprocessableEntity)
		return
	}

	r.Header.Add("X-APORETO-KEY", string(p.secrets.TransmittedKey()))
	r.Header.Add("X-APORETO-AUTH", token)

	p.fwdTLS.ServeHTTP(w, r)
}

func (p *Config) processNetRequest(w http.ResponseWriter, r *http.Request) {

	record := &collector.FlowRecord{
		ContextID: p.puContext,
		Destination: &collector.EndPoint{
			URI:  r.RequestURI,
			Type: collector.PU,
		},
		Source: &collector.EndPoint{
			Type: collector.PU,
		},
		Action: policy.Reject,
	}
	defer p.collector.CollectFlowEvent(record)

	pctx, err := p.puFromIDCache.Get(p.puContext)
	if err != nil {
		zap.L().Error("Cannot find policy, dropping request")
		http.Error(w, fmt.Sprintf("Cannot handle request: %s", err), http.StatusForbidden)
		return
	}
	record.Tags = pctx.(*pucontext.PUContext).Annotations()
	record.Destination.ID = pctx.(*pucontext.PUContext).ManagementID()

	token := r.Header.Get("X-APORETO-AUTH")
	if token != "" {
		r.Header.Del("X-APORETO-AUTH")
	}

	key := r.Header.Get("X-APORETO-KEY")
	if key != "" {
		r.Header.Del("X-APORETO-LEN")
	}

	port := "80"
	if strings.Contains(r.Host, ":") {
		_, port, err = net.SplitHostPort(r.Host)
		if err != nil {
			zap.L().Error("Invalid HTTP port parameter", zap.Error(err))
			http.Error(w, fmt.Sprintf("Invalid HTTP port parameter: %s", err), http.StatusUnprocessableEntity)
			return
		}
	}
	_port, _ := strconv.Atoi(port)
	record.Destination.Port = uint16(_port)

	data, err := p.exposedAPICache.Get(p.puContext)
	if err != nil {
		zap.L().Error("API service not recognized", zap.Error(err))
		http.Error(w, fmt.Sprintf("API service not recognized: %s", err), http.StatusUnprocessableEntity)
		return
	}

	apiCaches := data.(map[string]*urisearch.APICache)
	apiCache, ok := apiCaches[port]
	if !ok {
		zap.L().Error("Uknown service", zap.Error(err))
		http.Error(w, fmt.Sprintf("Unknown service: %s", err), http.StatusUnprocessableEntity)
		return
	}

	jwtcache, err := p.jwtCache.Get(p.puContext)
	if err != nil {
		zap.L().Warn("No JWT cache found for this pu", zap.Error(err))
	}

	jwtCert, ok := jwtcache.(map[string]*x509.Certificate)[port]
	if !ok {
		zap.L().Warn("No JWT found for this port")
	}

	found, t := apiCache.Find(r.Method, r.RequestURI)
	if !found {
		zap.L().Error("Uknown  or unauthorized service", zap.Error(err))
		http.Error(w, fmt.Sprintf("Unknown or unauthorized service"), http.StatusForbidden)
		return
	}

	userAttributes := parseUserAttributes(r, jwtCert)
	if len(userAttributes) > 0 {
		userRecord := &collector.UserRecord{Claims: userAttributes}
		p.collector.CollectUserEvent(userRecord)
		record.Source.UserID = userRecord.ID
	}

	if err = p.parseClientToken(pctx.(*pucontext.PUContext), token, key, t.([]string), userAttributes, record); err != nil {
		zap.L().Error("Unauthorized request", zap.Error(err))
		http.Error(w, fmt.Sprintf("Unauthorized access: %s", err), http.StatusUnauthorized)
		return
	}

	r.URL, err = url.ParseRequestURI("http://localhost:" + port)
	if err != nil {
		zap.L().Error("Invalid HTTP Host parameter", zap.Error(err))
		http.Error(w, fmt.Sprintf("Invalid HTTP Host parameter: %s", err), http.StatusUnprocessableEntity)
		return
	}

	record.Action = policy.Accept
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

func (p *Config) parseClientToken(puContext *pucontext.PUContext, token string, txtKey string, apitags []string, userAttributes []string, record *collector.FlowRecord) error {
	for _, user := range userAttributes {
		for _, a := range apitags {
			if user == a {
				return nil
			}
		}
	}

	key, err := p.secrets.VerifyPublicKey([]byte(txtKey))
	if err != nil {
		return fmt.Errorf("Invalid Service Token")
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
		return fmt.Errorf("Error parsing token: %s", err)
	}
	record.Source.ID = claims.SourceID

	for _, c := range claims.Profile {
		for _, a := range apitags {
			if a == c {
				return nil
			}
		}
	}

	for _, c := range claims.Scopes {
		for _, a := range apitags {
			if a == c {
				return nil
			}
		}
	}

	zap.L().Warn("No match found in API token",
		zap.Strings("User Attributes", userAttributes),
		zap.Strings("API Policy", apitags),
		zap.Strings("PU Claims", claims.Profile),
		zap.Strings("PU Scopes", claims.Scopes),
	)
	return fmt.Errorf("Not found")
}

func (p *Config) isSecretsRequest(w http.ResponseWriter, r *http.Request) bool {

	data, err := p.dependentAPICache.Get(p.puContext)
	if err != nil {
		http.Error(w, fmt.Sprintf("Cannot handle request - unknown dependencies: %s", err), http.StatusForbidden)
		return false
	}

	port := "80"
	host := r.Host
	if strings.Contains(r.Host, ":") {
		host, port, err = net.SplitHostPort(r.Host)
		if err != nil {
			zap.L().Error("Invalid HTTP port parameter", zap.Error(err))
			http.Error(w, fmt.Sprintf("Invalid HTTP port parameter: %s", err), http.StatusUnprocessableEntity)
			return false
		}
	}

	apiCache, ok := data.(map[string]*urisearch.APICache)[host+":"+port]
	if !ok {
		return false
	}

	// Look for a local request for certificates
	if found, _ := apiCache.Find(r.Method, r.RequestURI); !found {
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

func getServerName(addr string) string {
	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		return parts[0]
	}
	return addr
}

// InternalMidgardClaims HACK: Remove
type InternalMidgardClaims struct {
	Realm string            `json:"realm"`
	Data  map[string]string `json:"data"`

	jwt.StandardClaims
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
		switch token.Method {
		case token.Method.(*jwt.SigningMethodECDSA):
			return cert.PublicKey.(*ecdsa.PublicKey), nil
		case token.Method.(*jwt.SigningMethodRSA):
			return cert.PublicKey.(*rsa.PublicKey), nil
		default:
			return nil, fmt.Errorf("Unknown signing method")
		}
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
