package policy

import (
	"go.aporeto.io/trireme-lib/common"
)

// ServiceType are the types of services that can are suported.
type ServiceType int

// Values of ServiceType
const (
	ServiceL3 ServiceType = iota
	ServiceHTTP
	ServiceTCP
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

	// Type is the type of the service.
	Type ServiceType

	// HTTPRules are only valid for HTTP Services and capture the list of APIs
	// exposed by the service.
	HTTPRules []*HTTPRule

	// Tags are the tags of the service.
	Tags *TagStore

	// JWTCertificate is a certificate for validating JWT bearer tokens in http requests.
	// It is only useful for HTTP services where the Bearer Authentication header provides
	// a JWT token. It is used to validate the JWT tokens.
	JWTCertificate []byte

	// External indicates if this is an external service. For external services
	// access control is implemented at the ingress.
	External bool

	// CACert is the certificate of the CA of external services. This allows TLS to
	// work with external services that use private CAs.
	CACert []byte
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

	// Scopes is a list of scopes associated with this rule. Clients
	// must present one of these scopes in order to get access to this
	// API. The scopes are presented either in the Trireme identity or the
	// JWT of HTTP Authorization header.
	Scopes []string

	// Public indicates that this is a public API and anyone can access it.
	// No authorization will be performed on public APIs.
	Public bool
}
