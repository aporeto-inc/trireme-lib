package apiauth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.aporeto.io/trireme-lib/v11/collector"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/servicetokens"
	"go.aporeto.io/trireme-lib/v11/policy"
	"go.uber.org/zap"
)

const (
	defaultValidity = 60 * time.Second

	// TriremeOIDCCallbackURI is the callback URI that must be presented by
	// any OIDC provider.
	TriremeOIDCCallbackURI = "/aporeto/oidc/callback"
)

// Processor is an API Authorization processor.
type Processor struct {
	puContext string
	registry  *serviceregistry.Registry

	issuer  string // the issuer ID .. need to get rid of that part with the new tokens
	secrets secrets.Secrets
	sync.RWMutex
}

// New will create a new authorization processor.
func New(contextID string, r *serviceregistry.Registry, s secrets.Secrets) *Processor {
	return &Processor{
		puContext: contextID,
		registry:  r,
		secrets:   s,
	}
}

func (p *Processor) retrieveNetworkContext(originalIP *net.TCPAddr) (*serviceregistry.PortContext, error) {

	return p.registry.RetrieveExposedServiceContext(originalIP.IP, originalIP.Port, "")
}

func (p *Processor) retrieveApplicationContext(address *net.TCPAddr) (*serviceregistry.ServiceContext, *serviceregistry.DependentServiceData, error) {

	return p.registry.RetrieveServiceDataByIDAndNetwork(p.puContext, address.IP, address.Port, "")
}

// UpdateSecrets is called to update the authorizer secrets.
func (p *Processor) UpdateSecrets(s secrets.Secrets) {
	p.Lock()
	defer p.Unlock()

	p.secrets = s
}

// ApplicationRequest processes an application side request and returns
// the token that is associated with this application, together with an
// error if the request must be rejected.
func (p *Processor) ApplicationRequest(r *Request) (*AppAuthResponse, error) {

	d := &AppAuthResponse{
		TLSListener: true,
	}

	// Derive the service context for this request. This is another PU
	// or some external service. Context is derived based on the original
	// destination of the request.
	sctx, serviceData, err := p.retrieveApplicationContext(r.OriginalDestination)
	if err != nil {
		return d, &AuthError{
			status:  http.StatusBadGateway,
			message: fmt.Sprintf("Cannot identify application context: %s", err),
		}
	}
	d.PUContext = sctx.PUContext
	d.ServiceID = serviceData.APICache.ID

	// First we process network type rules (L3 based decision)
	_, netaction, noNetAccesPolicy := sctx.PUContext.ApplicationACLPolicyFromAddr(r.OriginalDestination.IP, uint16(r.OriginalDestination.Port))
	d.NetworkPolicyID = netaction.PolicyID
	d.NetworkServiceID = netaction.ServiceID
	if noNetAccesPolicy == nil && netaction.Action.Rejected() {
		return d, &AuthError{
			status:  http.StatusNetworkAuthenticationRequired,
			message: "Unauthorized Service - Rejected Outgoing Request by Network Policies",
		}
	}

	// For external services we validate policy at the ingress.
	if serviceData.APICache.External {
		d.External = true

		// Get the corresponding scopes
		found, rule := serviceData.APICache.FindRule(r.Method, r.URL.Path)
		if !found {
			return d, &AuthError{
				status:  http.StatusForbidden,
				message: "Uknown or unauthorized service: policy not found",
			}
		}
		d.HookMethod = rule.HookMethod
		// If there is an authorization policy attached to the rule, we must validate
		// against the identity of the PU.
		if !rule.Public {
			// Validate the policy based on the scopes of the PU.
			// TODO: Add user scopes
			if !serviceData.APICache.MatchClaims(rule.ClaimMatchingRules, append(sctx.PUContext.Identity().Tags, sctx.PUContext.Scopes()...)) {
				return d, &AuthError{
					status:  http.StatusForbidden,
					message: "Unauthorized service: rejected by policy",
				}
			}
		}

		d.Action = policy.Accept
		if !serviceData.ServiceObject.NoTLSExternalService {
			d.Action = d.Action | policy.Encrypt
		}
		d.TLSListener = !serviceData.ServiceObject.NoTLSExternalService

		return d, nil
	}

	p.RLock()
	defer p.RUnlock()

	secret := p.secrets

	token, err := servicetokens.CreateAndSign(
		p.issuer,
		sctx.PUContext.Identity().Tags,
		sctx.PUContext.Scopes(),
		sctx.PUContext.ManagementID(),
		defaultValidity,
		secret.EncodingKey(),
	)
	if err != nil {
		return d, &AuthError{
			status:  http.StatusInternalServerError,
			message: "Unable to issue service token",
			err:     err,
		}
	}

	d.Token = token

	return d, nil
}

// NetworkRequest authorizes a network request and either accepts the request
// or potentially issues a redirect.
func (p *Processor) NetworkRequest(ctx context.Context, r *Request) (*NetworkAuthResponse, error) {

	// First retrieve the context and policy for this request. Network
	// requests are indexed based on the original destination and port.
	pctx, err := p.retrieveNetworkContext(r.OriginalDestination)
	if err != nil {
		return nil, &AuthError{
			status:  http.StatusInternalServerError,
			message: "Internal server error - cannot identify destination policy",
			err:     err,
		}
	}

	// Create a basic response. We will update this response with information
	// as we continue processing.
	d := &NetworkAuthResponse{
		PUContext:   pctx.PUContext,
		ServiceID:   pctx.Service.ID,
		Action:      policy.Reject,
		SourceType:  collector.EndPointTypeExternalIP,
		TLSListener: pctx.Service.PrivateTLSListener,
		Namespace:   pctx.PUContext.ManagementNamespace(),
	}

	// We process first OIDC callbacks. These are the redirects after a user
	// has been authorized. We do not apply any network rule checks in this
	// case. If the callback is authorized we return the cookie and JWT
	// for the user.
	if strings.HasPrefix(r.RequestURI, TriremeOIDCCallbackURI) {
		callbackResponse, err := pctx.Authorizer.Callback(ctx, r.URL)
		if err == nil {
			d.Action = policy.Accept | policy.Encrypt
			d.Redirect = true
			d.RedirectURI = callbackResponse.OriginURL
			d.Cookie = callbackResponse.Cookie
			d.Data = callbackResponse.Data
			d.SourceType = collector.EndpointTypeClaims
			d.NetworkPolicyID = "default"
			d.NetworkServiceID = "default"
		}
		return d, &AuthError{
			message: callbackResponse.Message,
			status:  callbackResponse.Status,
		}
	}

	// We first process the network access rules based on external networks or
	// incoming IP addresses. We cannot process yet the Aporeto authorization
	// rules until after we decode the claims. The aclPolicy holds the matched
	// rules. If the method returns no error we store it in the noNetAccessPolicy
	// variable. This indicates that we have found no external network rule that
	// allows the request and we must validate the PU to PU rules. We will not
	// know what to do until after we decode all the incoming claims.
	// We perform this function early so that we don't waste CPU cycles with
	// processing tokens if the network policy does not allow the connection.
	_, aclPolicy, noNetAccessPolicy := pctx.PUContext.NetworkACLPolicyFromAddr(
		r.SourceAddress.IP,
		uint16(r.OriginalDestination.Port),
	)
	d.NetworkPolicyID = aclPolicy.PolicyID
	d.NetworkServiceID = aclPolicy.ServiceID
	if noNetAccessPolicy == nil && aclPolicy.Action.Rejected() {
		d.DropReason = collector.PolicyDrop
		d.SourceType = collector.EndPointTypeExternalIP
		return d, &AuthError{
			message: "Access denied by network policy",
			status:  http.StatusNetworkAuthenticationRequired,
		}
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
	userCredentials(ctx, pctx, r, d)

	// Calculate the Aporeto PU claims by parsing the token if it exists. If the token
	// is empty the DecodeAporetoClaims method will return no error.
	var aporetoClaims []string
	d.SourcePUID, aporetoClaims, err = pctx.Authorizer.DecodeAporetoClaims(token, key)
	if err != nil {
		d.DropReason = collector.PolicyDrop
		return d, &AuthError{
			message: fmt.Sprintf("Invalid Authorization Token: %s", err),
			status:  http.StatusForbidden,
		}
	}

	// If the other side is a PU we will always put the source type as PU.
	isPUSource := false
	if len(aporetoClaims) > 0 {
		isPUSource = true
		d.SourceType = collector.EnpointTypePU
	}

	// We need to verify network policy, before validating the API policy. If a network
	// policy has given us an accept because of IP address based ACLs we proceed anyway.
	// This is rather convoluted, but a user might choose to implement network
	// policies with ACLs only, and we have to cover this case.
	if noNetAccessPolicy != nil {

		// If we have not found an IP based access policy and the other side
		// is a PU we can visit the network rules based on tag authorization.
		if len(aporetoClaims) > 0 {
			_, netPolicyAction := pctx.PUContext.SearchRcvRules(policy.NewTagStoreFromSlice(aporetoClaims))
			d.NetworkPolicyID = netPolicyAction.PolicyID
			d.NetworkServiceID = aclPolicy.ServiceID
			if netPolicyAction.Action.Rejected() {
				d.DropReason = collector.PolicyDrop
				return d, &AuthError{
					message: "Access not authorized by network policy",
					status:  http.StatusNetworkAuthenticationRequired,
				}
			}
		} else {
			// If no network access policy and no PU claims, this request
			// is dropped.
			d.DropReason = collector.PolicyDrop
			return d, &AuthError{
				message: "Access denied by network policy: no policy found",
				status:  http.StatusNetworkAuthenticationRequired,
			}

		}
	} else {
		if aclPolicy.Action.Accepted() {
			aporetoClaims = append(aporetoClaims, aclPolicy.Labels...)
		}
	}

	// We can now validate the API authorization. This is the final step
	// before forwarding.
	allClaims := append(aporetoClaims, d.UserAttributes...)
	accept, public := pctx.Authorizer.Check(r.Method, r.URL.Path, allClaims)
	if !accept && !public {
		// If the authorization check returns reject, we need to validate
		// if this is a public request, it will be accepted.
		d.DropReason = collector.APIPolicyDrop

		// We need to process the redirects here. The reject might be forcing
		// us to issue a redirect. Redirects are valid only if the source
		// is a user. It doesn't make sense to redirect a PU.
		if !isPUSource {
			authError := &AuthError{
				message: "No token presented or invalid token: Please authenticate first",
				status:  http.StatusTemporaryRedirect,
			}
			if d.Redirect {
				d.RedirectURI = pctx.Authorizer.RedirectURI(r.URL.String())
				return d, authError
			} else if len(pctx.Service.UserRedirectOnAuthorizationFail) > 0 {
				d.RedirectURI = pctx.Service.UserRedirectOnAuthorizationFail + "?failure_message=authorization"
				return d, authError
			}
		}

		zap.L().Debug("No match found for the request or authorization Error",
			zap.String("Request", r.Method+" "+r.RequestURI),
			zap.Strings("User Attributes", d.UserAttributes),
			zap.Strings("Aporeto Claims", aporetoClaims),
		)

		return d, &AuthError{
			message: fmt.Sprintf("Unauthorized Access to %s", r.URL),
			status:  http.StatusUnauthorized,
		}
	}

	d.Action = policy.Accept
	if r.TLS != nil {
		d.Action = d.Action | policy.Encrypt
	}
	// We update the request headers with the claims and pass back
	// the information.
	pctx.Authorizer.UpdateRequestHeaders(r.Header, d.UserAttributes)
	d.Header = r.Header

	return d, nil

}

// userCredentials will find all the user credentials in the http request.
// TODO: In addition to looking at the headers, we need to look at the parameters
// in case authorization is provided there.
// It will return the userAttributes and a boolean instructing whether a redirect
// must be performed. If no user credentials are found, it will allow processing
// to proceed. It might be a
func userCredentials(ctx context.Context, pctx *serviceregistry.PortContext, r *Request, d *NetworkAuthResponse) {
	if r.TLS == nil {
		return
	}

	userCerts := r.TLS.PeerCertificates

	var userToken string
	authToken := r.Header.Get("Authorization")
	if len(authToken) < 7 {
		if r.Cookie != nil {
			userToken = r.Cookie.Value
		}
	} else {
		userToken = strings.TrimPrefix(authToken, "Bearer ")
	}

	userAttributes, redirect, refreshedToken, err := pctx.Authorizer.DecodeUserClaims(ctx, pctx.Service.ID, userToken, userCerts)
	if err != nil {
		zap.L().Warn("Partially failed to extract and decode user claims", zap.Error(err))
	}

	if len(userAttributes) > 0 {
		d.SourceType = collector.EndpointTypeClaims
	}

	if refreshedToken != userToken {
		d.Cookie = &http.Cookie{
			Name:     "X-APORETO-AUTH",
			Value:    refreshedToken,
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
		}
	}

	d.UserAttributes = userAttributes
	d.Redirect = redirect
}

func processHeaders(r *Request) (string, string) {
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
