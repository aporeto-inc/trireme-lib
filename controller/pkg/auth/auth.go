package auth

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/servicetokens"
	"go.aporeto.io/trireme-lib/controller/pkg/urisearch"
	"go.aporeto.io/trireme-lib/controller/pkg/usertokens"
	"go.aporeto.io/trireme-lib/policy"
)

// Processor holds all the local data of the authorization engine. A processor
// can handle authorization for multiple services. The goal is to authenticate
// a request based on both service and user credentials.
type Processor struct {
	apis                  *urisearch.APICache
	userTokenHandler      usertokens.Verifier
	userTokenMappings     map[string]string
	userAuthorizationType policy.UserAuthorizationTypeValues
	aporetoJWT            *servicetokens.Verifier
	sync.RWMutex
}

// NewProcessor creates an auth processor with PKI user tokens. The caller
// must provide a valid secrets structure and an optional list of trustedCertificates
// that can be used to validate tokens. If the list is empty, the CA from the secrets
// will be used for token validation.
func NewProcessor(s secrets.Secrets, trustedCertificate *x509.Certificate) *Processor {
	return &Processor{
		aporetoJWT: servicetokens.NewVerifier(s, trustedCertificate),
	}
}

// UpdateSecrets will update the Aporeto secrets for the validation of the
// Aporeto tokens.
func (p *Processor) UpdateSecrets(s secrets.Secrets, trustedCertificate *x509.Certificate) {
	p.aporetoJWT.UpdateSecrets(s, trustedCertificate)
}

// AddOrUpdateService adds or replaces a service in the authorization db.
func (p *Processor) AddOrUpdateService(apis *urisearch.APICache, serviceType policy.UserAuthorizationTypeValues, handler usertokens.Verifier, mappings map[string]string) {
	p.Lock()
	defer p.Unlock()

	p.apis = apis
	p.userTokenMappings = mappings
	p.userTokenHandler = handler
	p.userAuthorizationType = serviceType
}

// UpdateServiceAPIs updates an existing service with a new API definition.
func (p *Processor) UpdateServiceAPIs(apis *urisearch.APICache) error {
	p.Lock()
	defer p.Unlock()

	p.apis = apis
	return nil
}

// DecodeUserClaims decodes the user claims with the user authorization method.
func (p *Processor) DecodeUserClaims(name, userToken string, certs []*x509.Certificate, r *http.Request) ([]string, bool, error) {

	switch p.userAuthorizationType {
	case policy.UserAuthorizationMutualTLS:
		// First parse any incoming certificates and retrieve attributes from them.
		// This is used in case of client authorization with certificates.
		attributes := []string{}
		for _, cert := range certs {
			attributes = append(attributes, "CN="+cert.Subject.CommonName)
			for _, email := range cert.EmailAddresses {
				attributes = append(attributes, "Email="+email)
			}
			for _, org := range cert.Subject.Organization {
				attributes = append(attributes, "O="+org)
			}
			for _, org := range cert.Subject.OrganizationalUnit {
				attributes = append(attributes, "OU="+org)
			}
		}
		return attributes, false, nil
	case policy.UserAuthorizationOIDC, policy.UserAuthorizationJWT:
		// Now we can parse the user claims.
		if p.userTokenHandler == nil {
			return []string{}, false, nil
		}
		return p.userTokenHandler.Validate(r.Context(), userToken)
	default:
		return []string{}, false, nil
	}
}

// DecodeAporetoClaims decodes the Aporeto claims
func (p *Processor) DecodeAporetoClaims(aporetoToken string, publicKey string) (string, []string) {
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
func (p *Processor) Callback(w http.ResponseWriter, r *http.Request) {
	p.RLock()
	defer p.RUnlock()

	// Validate the JWT token through the handler.
	token, originURL, status, err := p.userTokenHandler.Callback(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid code %s:", err), http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:     "X-APORETO-AUTH",
		Value:    token,
		HttpOnly: true,
		Path:     "/",
		// Expires:  time.Now().Add(1 * time.Minute),
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
}

// Check is the main method that will search API cache and validate whether the call should
// be allowed. It returns two values. If the access is allowed, and whether the access
// public or not. This allows callers to decide what to do when there is a failure, and
// potentially issue a redirect.
func (p *Processor) Check(method, uri string, claims []string) (bool, bool) {
	p.RLock()
	defer p.RUnlock()

	return p.apis.FindAndMatchScope(method, uri, claims)
}

// RedirectURI returns the redirect URI in order to start the authentication dance.
func (p *Processor) RedirectURI(originURL string) string {
	p.RLock()
	defer p.RUnlock()

	return p.userTokenHandler.IssueRedirect(originURL)
}

// UpdateRequestHeaders will update the request headers based on the user claims
// and the corresponding mappings.
func (p *Processor) UpdateRequestHeaders(r *http.Request, claims []string) {
	p.RLock()
	defer p.RUnlock()

	if len(p.userTokenMappings) == 0 {
		return
	}

	for _, claim := range claims {
		parts := strings.SplitN(claim, "=", 2)
		if header, ok := p.userTokenMappings[parts[0]]; ok && len(parts) == 2 {
			r.Header.Add(header, parts[1])
		}
	}
}

// RetrieveServiceHandler will retrieve the service that is stored in the serviceMap
func (p *Processor) RetrieveServiceHandler() (usertokens.Verifier, error) {
	return p.userTokenHandler, nil
}
