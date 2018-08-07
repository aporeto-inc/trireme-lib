package auth

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/servicetokens"
	"go.aporeto.io/trireme-lib/controller/pkg/urisearch"
	"go.aporeto.io/trireme-lib/controller/pkg/usertokens"
)

type service struct {
	apis                 *urisearch.APICache
	userJWThandler       usertokens.Verifier
	userJWTClaimMappings map[string]string
}

// Processor holds all the local data of the authorization engine. A processor
// can handle authorization for multiple services. The goal is to authenticate
// a request based on both service and user credentials.
type Processor struct {
	serviceMap map[string]*service
	aporetoJWT *servicetokens.Verifier
	sync.RWMutex
}

// NewProcessor creates an auth processor with PKI user tokens. The caller
// must provide a valid secrets structure and an optional list of trustedCertificates
// that can be used to validate tokens. If the list is empty, the CA from the secrets
// will be used for token validation.
func NewProcessor(s secrets.Secrets, trustedCertificate *x509.Certificate) *Processor {
	return &Processor{
		serviceMap: map[string]*service{},
		aporetoJWT: servicetokens.NewVerifier(s, trustedCertificate),
	}
}

// UpdateSecrets will update the Aporeto secrets for the validation of the
// Aporeto tokens.
func (p *Processor) UpdateSecrets(s secrets.Secrets, trustedCertificate *x509.Certificate) {
	p.aporetoJWT.UpdateSecrets(s, trustedCertificate)
}

// AddOrUpdateService adds or replaces a service in the authorization db.
func (p *Processor) AddOrUpdateService(name string, apis *urisearch.APICache, handler usertokens.Verifier, mappings map[string]string) {
	p.Lock()
	defer p.Unlock()

	p.serviceMap[name] = &service{
		apis:                 apis,
		userJWThandler:       handler,
		userJWTClaimMappings: mappings,
	}
}

// RemoveService removes a service from the authorization db
func (p *Processor) RemoveService(name string) {
	p.Lock()
	defer p.Unlock()

	delete(p.serviceMap, name)
}

// UpdateServiceAPIs updates an existing service with a new API definition.
func (p *Processor) UpdateServiceAPIs(name string, apis *urisearch.APICache) error {
	p.Lock()
	defer p.Unlock()

	if srv, ok := p.serviceMap[name]; ok {
		srv.apis = apis
		return nil
	}

	return fmt.Errorf("Service not found")
}

// DecodeUserClaims decodes the user claims with the user authorization method.
func (p *Processor) DecodeUserClaims(name, userToken string, certs []*x509.Certificate, r *http.Request) ([]string, bool, error) {
	attributes := []string{}

	srv, ok := p.serviceMap[name]
	if !ok {
		return attributes, false, nil
	}

	// First parse any incoming certificates and retrieve attributes from them.
	// This is used in case of client authorization with certificates.
	for _, cert := range certs {
		attributes = append(attributes, "user="+cert.Subject.CommonName)
		for _, email := range cert.EmailAddresses {
			attributes = append(attributes, "email="+email)
		}
		for _, org := range cert.Subject.Organization {
			attributes = append(attributes, "organization=", org)
		}
		for _, org := range cert.Subject.OrganizationalUnit {
			attributes = append(attributes, "ou=", org)
		}
	}

	// Now we can parse the user claims.
	if srv.userJWThandler == nil {
		return attributes, false, nil
	}
	claims, redirect, err := srv.userJWThandler.Validate(r.Context(), userToken)
	if err != nil {
		if len(attributes) == 0 {
			return attributes, redirect, err
		}
		return attributes, false, nil
	}

	return append(attributes, claims...), false, nil
}

// DecodeAporetoClaims decodes the Aporeto claims
func (p *Processor) DecodeAporetoClaims(name, aporetoToken string, publicKey string) (string, []string) {
	if len(aporetoToken) == 0 || p.aporetoJWT == nil {
		return "", []string{}
	}

	// Finally we can parse the Aporeto token.
	id, scopes, profile, err := p.aporetoJWT.ParseToken(aporetoToken, publicKey)
	if err != nil {
		return "", []string{}
	}
	return id, append(profile, scopes...)
}

// Callback is function called by and IDP auth provider will exchange the provided
// authorization code with a JWT token. This closes the Oauth loop.
func (p *Processor) Callback(name string, w http.ResponseWriter, r *http.Request) {
	p.RLock()
	defer p.RUnlock()

	// We first detect the service that is being called, in order to get the
	// right OAUTH context.
	srv, ok := p.serviceMap[name]
	if !ok {
		http.Error(w, "Unknown service", http.StatusInternalServerError)
		return
	}

	// Validate the JWT token through the handler.
	token, originURL, status, err := srv.userJWThandler.Callback(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid code %s:", err), http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:     "X-APORETO-AUTH",
		Value:    token,
		HttpOnly: true,
		Path:     "/",
		Expires:  time.Now().Add(1 * time.Minute),
	}

	http.SetCookie(w, cookie)

	// We transmit the information in the return payload for applications
	// that choose to use it directly without a cookie.
	data, err := json.MarshalIndent(cookie, " ", " ")
	if err != nil {
		http.Error(w, "Bad data", http.StatusInternalServerError)
		return
	}

	// We redirect here to the original URL that the application attempted
	// to access.
	w.Header().Add("Location", originURL)
	http.Error(w, string(data), status)

	return
}

// Check is the main method that will search API cache and validate whether the call should
// be allowed. It returns two values. If the access is allowed, and whether the access
// public or not. This allows callers to decide what to do when there is a failure, and
// potentially issue a redirect.
func (p *Processor) Check(name, method, uri string, claims []string) (bool, bool) {
	p.RLock()
	defer p.RUnlock()

	srv, ok := p.serviceMap[name]
	if !ok {
		return false, false
	}

	return srv.apis.FindAndMatchScope(method, uri, claims)
}

// RedirectURI returns the redirect URI in order to start the authentication dance.
func (p *Processor) RedirectURI(name string, originURL string) string {
	p.RLock()
	defer p.RUnlock()

	srv, ok := p.serviceMap[name]
	if !ok {
		return ""
	}
	//TODO: erropr hanmdlign
	return srv.userJWThandler.IssueRedirect(originURL)
}

// UpdateRequestHeaders will update the request headers based on the user claims
// and the corresponding mappings.
func (p *Processor) UpdateRequestHeaders(name string, r *http.Request, claims []string) {
	p.RLock()
	defer p.RUnlock()

	srv, ok := p.serviceMap[name]
	if !ok {
		return
	}

	if len(srv.userJWTClaimMappings) == 0 {
		return
	}

	for _, claim := range claims {
		parts := strings.SplitN(claim, "=", 2)
		if header, ok := srv.userJWTClaimMappings[parts[0]]; ok && len(parts) == 2 {
			r.Header.Add(header, parts[1])
		}
	}
}
