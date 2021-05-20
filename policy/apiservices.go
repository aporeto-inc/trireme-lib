package policy

import (
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/usertokens"
)

// ServiceType are the types of services that can are suported.
type ServiceType int

// Values of ServiceType
const (
	ServiceL3 ServiceType = iota
	ServiceHTTP
	ServiceTCP
	ServiceSecretsProxy
)

// ServiceTLSType is the types of TLS used on public port
type ServiceTLSType int

// Values of UserAuthorizationTypeValues
const (
	ServiceTLSTypeNone ServiceTLSType = iota
	ServiceTLSTypeAporeto
	ServiceTLSTypeCustom
)

// UserAuthorizationTypeValues is the types of user authorization methods that
// are supported.
type UserAuthorizationTypeValues int

// Values of UserAuthorizationTypeValues
const (
	UserAuthorizationNone UserAuthorizationTypeValues = iota
	UserAuthorizationMutualTLS
	UserAuthorizationJWT
	UserAuthorizationOIDC
)

// ApplicationServicesList is a list of ApplicationServices.
type ApplicationServicesList []*ApplicationService

// ApplicationService is the type of service that this PU exposes.
type ApplicationService struct {
	// ID is the id of the service
	ID string

	// NetworkInfo provides the network information (addresses/ports) of the service.
	// This is the public facing network information, or how the service can be
	// accessed. In the case of Load Balancers for example, this would be the
	// IP/port of the load balancer.
	NetworkInfo *common.Service

	// PrivateNetworkInfo captures the network service definition of an application
	// as seen by the application. For example the port that the application is
	// listening to. This is needed in the case of port mappings.
	PrivateNetworkInfo *common.Service

	// PrivateTLSListener indicates that the service uses a TLS listener. As a
	// result we must TLS for traffic send locally in the service.
	PrivateTLSListener bool

	// NoTLSExternalService indicates that TLS should not be used for an external
	// service. This option is used for API calls to local metadata APIs and
	// should not be used for access to the Internet.
	NoTLSExternalService bool

	// PublicNetworkInfo provides the network information where the enforcer
	// should listen for incoming connections of the service. This can be
	// different than the PrivateNetworkInfo where the application is listening
	// and it essentially allows users to create Virtual IPs and Virtual Ports
	// for the new exposed TLS services. So, if an application is listening
	// on port 80, users do not need to access the application from external
	// network through TLS on port 80, that looks weird. They can instead create
	// a PublicNetworkInfo and have the trireme listen on port 443, while the
	// application is still listening on port 80.
	PublicNetworkInfo *common.Service

	// Type is the type of the service.
	Type ServiceType

	// HTTPRules are only valid for HTTP Services and capture the list of APIs
	// exposed by the service.
	HTTPRules []*HTTPRule

	// Tags are the tags of the service.
	Tags []string

	// FallbackJWTAuthorizationCert is the certificate that has been used to sign
	// JWTs if they are not signed by the datapath
	FallbackJWTAuthorizationCert string

	// UserAuthorizationType is the type of user authorization that must be used.
	UserAuthorizationType UserAuthorizationTypeValues

	// UserAuthorizationHandler is the token handler for validating user tokens.
	UserAuthorizationHandler usertokens.Verifier

	// UserTokenToHTTPMappings is a map of mappings between JWT claims arriving in
	// a user request and outgoing HTTP headers towards an application. It
	// is used to allow operators to map claims to HTTP headers that downstream
	// applications can understand.
	UserTokenToHTTPMappings map[string]string

	// UserRedirectOnAuthorizationFail is the URL that the user can be redirected
	// if there is an authorization failure. This allows the display of a custom
	// message.
	UserRedirectOnAuthorizationFail string

	// External indicates if this is an external service. For external services
	// access control is implemented at the ingress.
	External bool

	// CACert is the certificate of the CA of external services. This allows TLS to
	// work with external services that use private CAs.
	CACert []byte

	// AuthToken is the authentication token for any external API service calls. It is
	// used for example by the secrets proxy.
	AuthToken string

	// MutualTLSTrustedRoots is the CA that must be used for mutual TLS authentication.
	MutualTLSTrustedRoots []byte

	// PublicServiceCertificate is a publically signed certificate that can be used
	// by the service to expose TLS to users without a Trireme client
	PublicServiceCertificate []byte

	// PublicServiceCertificateKey is the corresponding private key.
	PublicServiceCertificateKey []byte

	// PublicServiceTLSType specifies TLS Type to support on PublicService port.
	// This is useful for health checks. It should not be used for API access.
	PublicServiceTLSType ServiceTLSType
}

// HTTPRule holds a rule for a particular HTTPService. The rule
// relates a set of URIs defined as regular expressions with associated
// verbs. The * VERB indicates all actions.
type HTTPRule struct {
	// URIs is a list of regular expressions that describe the URIs that
	// a service is exposing.
	URIs []string

	// Methods is a list of the allowed verbs for the given list of URIs.
	Methods []string

	// ClaimMatchingRules is a list of matching rules associated with this rule. Clients
	// must present a set of claims that will satisfy these rules. Each rule
	// is an AND clause. The list of expressions is an OR of the AND clauses.
	ClaimMatchingRules [][]string

	// Public indicates that this is a public API and anyone can access it.
	// No authorization will be performed on public APIs.
	Public bool

	// HookMethod indicates that this rule is not for generic proxying but
	// must first be processed by the hook with the corresponding name.
	HookMethod string
}

// PublicPort returns the min port in the spec for the publicly exposed port.
func (a *ApplicationService) PublicPort() int {
	if a.PublicNetworkInfo == nil {
		return 0
	}
	return int(a.PublicNetworkInfo.Ports.Min)
}

// PrivatePort returns the min port in the spec for the private listening port.
func (a *ApplicationService) PrivatePort() int {
	if a.PrivateNetworkInfo == nil {
		return 0
	}
	return int(a.PrivateNetworkInfo.Ports.Min)
}
