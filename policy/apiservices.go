package policy

import (
	"github.com/aporeto-inc/trireme-lib/common"
)

// ServiceType are the types of services that can are suported.
type ServiceType int

// Values of ServiceType
const (
	ServiceTCP ServiceType = iota
	ServiceHTTP
	ServiceL3
)

// ApplicationServicesList is a list of ApplicationServices.
type ApplicationServicesList []*ApplicationService

// ApplicationService is the type of service that this PU exposes.
type ApplicationService struct {
	// NetworkInfo provides the network information (addresses/ports) of the service
	NetworkInfo *common.Service
	// Type is the type of the service.
	Type ServiceType
	// ApplicationRules are only valid for non TCP or L3 services
	HTTPRules []*HTTPRule
	// Tags are the tags of the service.
	Tags *TagStore
}

// HTTPRule holds a rule for a particular HTTPService. The rule
// relates a set of URIs defined as regular expressions with associated
// verbs. The * VERB indicates all actions.
type HTTPRule struct {
	// URIs is a list of regular expressions  that describe the URIs
	URIs []string
	// Verbs is a list of the allowed verbs
	Verbs []string
	// Tags is a list of tags associated with this rule. The tags will be
	// used for matching based on authorization.
	Tags *TagStore
}
