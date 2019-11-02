package auth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"go.aporeto.io/trireme-lib/v11/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/servicetokens"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/urisearch"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/usertokens"
	"go.aporeto.io/trireme-lib/v11/policy"
	"go.uber.org/zap"
)

// CallbackResponse captures all the response data of the call back processing.
type CallbackResponse struct {
	Cookie    *http.Cookie
	Status    int
	OriginURL string
	Data      string
	Message   string
}

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
func (p *Processor) DecodeUserClaims(ctx context.Context, name, userToken string, certs []*x509.Certificate) ([]string, bool, string, error) {

	switch p.userAuthorizationType {
	case policy.UserAuthorizationMutualTLS, policy.UserAuthorizationJWT:
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

		if p.userAuthorizationType == policy.UserAuthorizationJWT && p.userTokenHandler != nil {
			jwtAttributes, _, _, err := p.userTokenHandler.Validate(ctx, userToken)
			if err != nil {
				return attributes, false, userToken, fmt.Errorf("Unable to decode JWT: %s", err)
			}
			attributes = append(attributes, jwtAttributes...)
		}

		return attributes, false, userToken, nil

	case policy.UserAuthorizationOIDC:
		// Now we can parse the user claims.
		if p.userTokenHandler == nil {
			zap.L().Error("Internal Server Error: OIDC User Token Handler not configured")
			return []string{}, false, userToken, nil
		}
		return p.userTokenHandler.Validate(ctx, userToken)
	default:
		return []string{}, false, userToken, nil
	}
}

// DecodeAporetoClaims decodes the Aporeto claims
func (p *Processor) DecodeAporetoClaims(aporetoToken string, publicKey string) (string, []string, error) {
	if len(aporetoToken) == 0 || p.aporetoJWT == nil {
		return "", []string{}, nil
	}

	// Finally we can parse the Aporeto token.
	id, scopes, profile, err := p.aporetoJWT.ParseToken(aporetoToken, publicKey)
	if err != nil {
		return "", []string{}, fmt.Errorf("Invalid Aporeto Token: %s", err)
	}
	return id, append(profile, scopes...), nil
}

// Callback is function called by and IDP auth provider will exchange the provided
// authorization code with a JWT token. This closes the Oauth loop.
func (p *Processor) Callback(ctx context.Context, u *url.URL) (*CallbackResponse, error) {
	p.RLock()
	defer p.RUnlock()

	c := &CallbackResponse{}

	// Validate the JWT token through the handler.
	token, originURL, status, err := p.userTokenHandler.Callback(ctx, u)
	if err != nil {
		c.Status = http.StatusUnauthorized
		c.Message = fmt.Sprintf("Invalid code %s:", err)
		return c, err
	}

	c.OriginURL = originURL
	c.Status = status
	c.Cookie = &http.Cookie{
		Name:     "X-APORETO-AUTH",
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	}

	// We transmit the information in the return payload for applications
	// that choose to use it directly without a cookie.
	data, err := json.MarshalIndent(c.Cookie, " ", " ")
	if err != nil {
		c.Status = http.StatusInternalServerError
		c.Message = "Unable to decode data"
		return c, err
	}

	c.Data = string(data)

	return c, nil
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
func (p *Processor) UpdateRequestHeaders(h http.Header, claims []string) {
	p.RLock()
	defer p.RUnlock()

	if len(p.userTokenMappings) == 0 {
		return
	}

	for _, claim := range claims {
		parts := strings.SplitN(claim, "=", 2)
		if header, ok := p.userTokenMappings[parts[0]]; ok && len(parts) == 2 {
			h.Add(header, parts[1])
		}
	}
}

// RetrieveServiceHandler will retrieve the service that is stored in the serviceMap
func (p *Processor) RetrieveServiceHandler() (usertokens.Verifier, error) {
	return p.userTokenHandler, nil
}
