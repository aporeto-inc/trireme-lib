package policy

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/usertokens"
)

// EnforcerType defines which enforcer type should be selected
type EnforcerType int

const (
	// EnforcerMapping lets the default enforcer configuration deal with it
	EnforcerMapping EnforcerType = iota
	// EnvoyAuthorizerEnforcer specifically asks for running an envoy enforcer/authorizer
	EnvoyAuthorizerEnforcer
)

// String implements the string interface
func (t EnforcerType) String() string {
	switch t {
	case EnforcerMapping:
		return "EnforcerMapping"
	case EnvoyAuthorizerEnforcer:
		return "EnvoyAuthorizerEnforcer"
	default:
		return strconv.Itoa(int(t))
	}
}

// EnforcerTypeFromString parses `str` and tries to convert it to
func EnforcerTypeFromString(str string) (EnforcerType, error) {
	switch str {
	case "EnforcerMapping":
		return EnforcerMapping, nil
	case "EnvoyAuthorizerEnforcer":
		return EnvoyAuthorizerEnforcer, nil
	default:
		i, err := strconv.Atoi(str)
		if err != nil {
			return EnforcerMapping, fmt.Errorf("failed to parse enforcer type from string number (input '%s'): %s", str, err.Error())
		}
		if i < int(EnforcerMapping) {
			return EnforcerMapping, fmt.Errorf("failed to parse enforcer type from string number (input '%s'): below possible valid value", str)
		}
		if i > int(EnvoyAuthorizerEnforcer) {
			return EnforcerMapping, fmt.Errorf("failed to parse enforcer type from string number (input '%s'): above possible valid value", str)
		}

		return EnforcerType(i), nil
	}
}

// PUPolicy captures all policy information related ot the container
type PUPolicy struct {

	// ManagementID is provided for the policy implementations as a means of
	// holding a policy identifier related to the implementation.
	managementID string
	// managementNamespace is provided for the policy implementations as a means of
	// holding a policy sub identifier related to the implementation.
	managementNamespace string
	// triremeAction defines what level of policy should be applied to that container.
	triremeAction PUAction
	// dnsACLs is the list of DNS names and the associated ports that the container is
	// allowed to talk to outside the data center
	DNSACLs DNSRuleList
	// applicationACLs is the list of ACLs to be applied when the container talks
	// to IP Addresses outside the data center
	applicationACLs IPRuleList
	// networkACLs is the list of ACLs to be applied from IP Addresses outside
	// the data center
	networkACLs IPRuleList
	// identity is the set of key value pairs that must be send over the wire.
	identity *TagStore
	// compressedTags is the set of of compressed key/value pairs as binary values.
	compressedTags *TagStore
	// annotations are key/value pairs  that should be used for accounting reasons
	annotations *TagStore
	// transmitterRules is the set of rules that implement the label matching at the Transmitter
	transmitterRules TagSelectorList
	// teceiverRules is the set of rules that implement matching at the Receiver
	receiverRules TagSelectorList
	// ips is the set of IP addresses and namespaces that the policy must be applied to
	ips ExtendedMap
	// servicesListeningPort is the port that we will use for the proxy.
	servicesListeningPort int
	// dnsProxyPort is the proxy port that listens dns traffic
	dnsProxyPort int
	// exposedServices is the list of services that this PU is exposing.
	exposedServices ApplicationServicesList
	// dependentServices is the list of services that this PU depends on.
	dependentServices ApplicationServicesList
	// servicesCertificate is the services certificate
	servicesCertificate string
	// servicePrivateKey is the service private key
	servicesPrivateKey string
	// servicesCA is the CA to be used for the outgoing services
	servicesCA string
	// scopes are the processing unit granted scopes
	scopes []string
	// enforcerType is the enforcer type that is supposed to get used for this PU
	enforcerType EnforcerType
	// appDefaultPolicyAction is the application default action of the namespace
	appDefaultPolicyAction ActionType
	// netDefaultPolicyAction is the network default action of the namespace
	netDefaultPolicyAction ActionType
	// logPrefixMapping maps a short nlog prefix it it's long prefix
	logPrefixMapping map[string]string
	// logPrefixMappingCalculated is used to no when to calculate the log mapping
	logPrefixMappingCalculated bool

	sync.Mutex
}

// PUAction defines the action types that applies for a specific PU as a whole.
type PUAction int

const (
	// AllowAll allows everything for the specific PU.
	AllowAll = 0x1
	// Police filters on the PU based on the PolicyRules.
	Police = 0x2
)

// NewPUPolicy generates a new ContainerPolicyInfo
// appACLs are the ACLs for packet coming from the Application/PU to the Network.
// netACLs are the ACLs for packet coming from the Network to the Application/PU.
func NewPUPolicy(
	id string,
	namespace string,
	action PUAction,
	appACLs IPRuleList,
	netACLs IPRuleList,
	dnsACLs DNSRuleList,
	txtags TagSelectorList,
	rxtags TagSelectorList,
	identity *TagStore,
	annotations *TagStore,
	compressedTags *TagStore,
	ips ExtendedMap,
	servicesListeningPort int,
	dnsProxyPort int,
	exposedServices ApplicationServicesList,
	dependentServices ApplicationServicesList,
	scopes []string,
	enforcerType EnforcerType,
	appDefaultPolicyAction ActionType,
	netDefaultPolicyAction ActionType,
) *PUPolicy {

	if appACLs == nil {
		appACLs = IPRuleList{}
	}
	if netACLs == nil {
		netACLs = IPRuleList{}
	}
	if dnsACLs == nil {
		dnsACLs = DNSRuleList{}
	}
	if txtags == nil {
		txtags = TagSelectorList{}
	}
	if rxtags == nil {
		rxtags = TagSelectorList{}
	}

	if identity == nil {
		identity = NewTagStore()
	}

	if annotations == nil {
		annotations = NewTagStore()
	}

	if compressedTags == nil {
		compressedTags = NewTagStore()
	}

	if ips == nil {
		ips = ExtendedMap{}
	}

	if exposedServices == nil {
		exposedServices = ApplicationServicesList{}
	}

	if dependentServices == nil {
		dependentServices = ApplicationServicesList{}
	}

	return &PUPolicy{
		managementID:           id,
		managementNamespace:    namespace,
		triremeAction:          action,
		applicationACLs:        appACLs,
		networkACLs:            netACLs,
		DNSACLs:                dnsACLs,
		transmitterRules:       txtags,
		receiverRules:          rxtags,
		identity:               identity,
		compressedTags:         compressedTags,
		annotations:            annotations,
		ips:                    ips,
		servicesListeningPort:  servicesListeningPort,
		dnsProxyPort:           dnsProxyPort,
		exposedServices:        exposedServices,
		dependentServices:      dependentServices,
		scopes:                 scopes,
		enforcerType:           enforcerType,
		appDefaultPolicyAction: appDefaultPolicyAction,
		netDefaultPolicyAction: netDefaultPolicyAction,
	}
}

// NewPUPolicyWithDefaults sets up a PU policy with defaults
func NewPUPolicyWithDefaults() *PUPolicy {
	return NewPUPolicy("", "", AllowAll, nil, nil, nil, nil, nil, nil, nil, nil, nil, 0, 0, nil, nil, []string{}, EnforcerMapping, Reject|Log, Reject|Log)
}

// Clone returns a copy of the policy
func (p *PUPolicy) Clone() *PUPolicy {
	p.Lock()
	defer p.Unlock()

	np := NewPUPolicy(
		p.managementID,
		p.managementNamespace,
		p.triremeAction,
		p.applicationACLs.Copy(),
		p.networkACLs.Copy(),
		p.DNSACLs.Copy(),
		p.transmitterRules.Copy(),
		p.receiverRules.Copy(),
		p.identity.Copy(),
		p.annotations.Copy(),
		p.compressedTags.Copy(),
		p.ips.Copy(),
		p.servicesListeningPort,
		p.dnsProxyPort,
		p.exposedServices,
		p.dependentServices,
		p.scopes,
		p.enforcerType,
		p.appDefaultPolicyAction,
		p.netDefaultPolicyAction,
	)

	return np
}

// ManagementID returns the management ID
func (p *PUPolicy) ManagementID() string {
	p.Lock()
	defer p.Unlock()

	return p.managementID
}

// ManagementNamespace returns the management Namespace
func (p *PUPolicy) ManagementNamespace() string {
	p.Lock()
	defer p.Unlock()

	return p.managementNamespace
}

// TriremeAction returns the TriremeAction
func (p *PUPolicy) TriremeAction() PUAction {
	p.Lock()
	defer p.Unlock()

	return p.triremeAction
}

// SetTriremeAction returns the TriremeAction
func (p *PUPolicy) SetTriremeAction(action PUAction) {
	p.Lock()
	defer p.Unlock()

	p.triremeAction = action
}

// ApplicationACLs returns a copy of IPRuleList
func (p *PUPolicy) ApplicationACLs() IPRuleList {
	p.Lock()
	defer p.Unlock()

	return p.applicationACLs.Copy()
}

// NetworkACLs returns a copy of IPRuleList
func (p *PUPolicy) NetworkACLs() IPRuleList {
	p.Lock()
	defer p.Unlock()

	return p.networkACLs.Copy()
}

// DNSNameACLs returns a copy of DNSRuleList
func (p *PUPolicy) DNSNameACLs() DNSRuleList {
	p.Lock()
	defer p.Unlock()

	return p.DNSACLs.Copy()
}

// ReceiverRules returns a copy of TagSelectorList
func (p *PUPolicy) ReceiverRules() TagSelectorList {
	p.Lock()
	defer p.Unlock()

	return p.receiverRules.Copy()
}

// AddReceiverRules adds a receiver rule
func (p *PUPolicy) AddReceiverRules(t TagSelector) {
	p.Lock()
	defer p.Unlock()

	p.receiverRules = append(p.receiverRules, t)
}

// TransmitterRules returns a copy of TagSelectorList
func (p *PUPolicy) TransmitterRules() TagSelectorList {
	p.Lock()
	defer p.Unlock()

	return p.transmitterRules.Copy()
}

// AddTransmitterRules adds a transmitter rule
func (p *PUPolicy) AddTransmitterRules(t TagSelector) {
	p.Lock()
	defer p.Unlock()

	p.transmitterRules = append(p.transmitterRules, t)
}

// Identity returns a copy of the Identity
func (p *PUPolicy) Identity() *TagStore {
	p.Lock()
	defer p.Unlock()

	return p.identity.Copy()
}

// CompressedTags returns the compressed tags of the policy.
func (p *PUPolicy) CompressedTags() *TagStore {
	p.Lock()
	defer p.Unlock()

	return p.compressedTags.Copy()
}

// Annotations returns a copy of the annotations
func (p *PUPolicy) Annotations() *TagStore {
	p.Lock()
	defer p.Unlock()

	return p.annotations.Copy()
}

// AddIdentityTag adds a policy tag
func (p *PUPolicy) AddIdentityTag(k, v string) {
	p.Lock()
	defer p.Unlock()

	p.identity.AppendKeyValue(k, v)
}

// IPAddresses returns all the IP addresses for the processing unit
func (p *PUPolicy) IPAddresses() ExtendedMap {
	p.Lock()
	defer p.Unlock()

	return p.ips.Copy()
}

// SetIPAddresses sets the IP addresses for the processing unit
func (p *PUPolicy) SetIPAddresses(l ExtendedMap) {
	p.Lock()
	defer p.Unlock()

	p.ips = l
}

// ExposedServices returns the exposed services
func (p *PUPolicy) ExposedServices() ApplicationServicesList {
	p.Lock()
	defer p.Unlock()

	return p.exposedServices
}

// DNSProxyPort gets the dns proxy port
func (p *PUPolicy) DNSProxyPort() string {
	p.Lock()
	defer p.Unlock()

	return strconv.Itoa(p.dnsProxyPort)
}

// DependentServices returns the external services.
func (p *PUPolicy) DependentServices() ApplicationServicesList {
	p.Lock()
	defer p.Unlock()

	return p.dependentServices
}

// ServicesListeningPort returns the port that should be used by the proxies.
func (p *PUPolicy) ServicesListeningPort() string {
	p.Lock()
	defer p.Unlock()

	return strconv.Itoa(p.servicesListeningPort)
}

// UpdateDNSNetworks updates the set of FQDN names allowed by the policy
func (p *PUPolicy) UpdateDNSNetworks(networks DNSRuleList) {
	p.Lock()
	defer p.Unlock()

	for k, v := range networks {
		p.DNSACLs[k] = v
	}
}

// UpdateServiceCertificates updates the certificate and private key of the policy
func (p *PUPolicy) UpdateServiceCertificates(cert, key string) {
	p.Lock()
	defer p.Unlock()

	p.servicesCertificate = cert
	p.servicesPrivateKey = key
}

// ServiceCertificates returns the service certificate.
func (p *PUPolicy) ServiceCertificates() (string, string, string) {
	p.Lock()
	defer p.Unlock()

	return p.servicesCertificate, p.servicesPrivateKey, p.servicesCA
}

// Scopes returns the scopes of the policy.
func (p *PUPolicy) Scopes() []string {
	p.Lock()
	defer p.Unlock()

	return p.scopes
}

// EnforcerType returns the enforcer type of the policy.
func (p *PUPolicy) EnforcerType() EnforcerType {
	p.Lock()
	defer p.Unlock()

	return p.enforcerType
}

// AppDefaultPolicyAction returns default application action.
func (p *PUPolicy) AppDefaultPolicyAction() ActionType {
	p.Lock()
	defer p.Unlock()

	return p.appDefaultPolicyAction
}

// NetDefaultPolicyAction returns default network action.
func (p *PUPolicy) NetDefaultPolicyAction() ActionType {
	p.Lock()
	defer p.Unlock()

	return p.netDefaultPolicyAction
}

// ToPublicPolicy converts the object to a marshallable object.
func (p *PUPolicy) ToPublicPolicy() *PUPolicyPublic {
	p.Lock()
	defer p.Unlock()

	return &PUPolicyPublic{
		ManagementID:           p.managementID,
		ManagementNamespace:    p.managementNamespace,
		TriremeAction:          p.triremeAction,
		ApplicationACLs:        p.applicationACLs.Copy(),
		NetworkACLs:            p.networkACLs.Copy(),
		DNSACLs:                p.DNSACLs.Copy(),
		TransmitterRules:       p.transmitterRules.Copy(),
		ReceiverRules:          p.receiverRules.Copy(),
		Annotations:            p.annotations.GetSlice(),
		CompressedTags:         p.compressedTags.GetSlice(),
		Identity:               p.identity.GetSlice(),
		IPs:                    p.ips.Copy(),
		ServicesListeningPort:  p.servicesListeningPort,
		DNSProxyPort:           p.dnsProxyPort,
		ExposedServices:        p.exposedServices,
		DependentServices:      p.dependentServices,
		Scopes:                 p.scopes,
		ServicesCA:             p.servicesCA,
		ServicesCertificate:    p.servicesCertificate,
		ServicesPrivateKey:     p.servicesPrivateKey,
		EnforcerType:           p.enforcerType,
		AppDefaultPolicyAction: p.appDefaultPolicyAction,
		NetDefaultPolicyAction: p.netDefaultPolicyAction,
	}
}

// LookupLogPrefix returns the long version of the nlog prefix
func (p *PUPolicy) LookupLogPrefix(key string) (string, bool) {

	p.Lock()
	defer p.Unlock()

	// On demand calculate the mapping
	p.calculateLogPrefixes()

	logPrefix, ok := p.logPrefixMapping[key]
	return logPrefix, ok
}

// GetLogPrefixes returns the current map of logging prefixes
func (p *PUPolicy) GetLogPrefixes() map[string]string {

	p.Lock()
	defer p.Unlock()

	// On demand calculate the mapping
	p.calculateLogPrefixes()

	clone := map[string]string{}
	for key, value := range p.logPrefixMapping {
		clone[key] = value
	}
	return clone
}

// MergeLogPrefixes merges existing prefixes with the current logging prefixes
func (p *PUPolicy) MergeLogPrefixes(prefixes map[string]string) {

	p.Lock()
	defer p.Unlock()

	// On demand calculate the mapping
	p.calculateLogPrefixes()

	for key, value := range prefixes {
		p.logPrefixMapping[key] = value
	}
}

// calculateLogPrefixes calculates the short/long logging prefixes
func (p *PUPolicy) calculateLogPrefixes() {

	// On demand calculate the mapping
	if !p.logPrefixMappingCalculated {
		p.logPrefixMapping = map[string]string{}
		compute := func(ruleList IPRuleList) {
			for _, ipRule := range ruleList {
				if ipRule.Policy != nil {
					key, value := ipRule.Policy.GetShortAndLongLogPrefix()
					p.logPrefixMapping[key] = value
				}
			}
		}
		compute(p.applicationACLs)
		compute(p.networkACLs)

		// mapping has been calculated
		p.logPrefixMappingCalculated = true
	}
}

// PUPolicyPublic captures all policy information related ot the processing
// unit in an object that can be marshalled and transmitted over the RPC interface.
type PUPolicyPublic struct {
	ManagementID           string                  `json:"managementID,omitempty"`
	ManagementNamespace    string                  `json:"managementNamespace,omitempty"`
	TriremeAction          PUAction                `json:"triremeAction,omitempty"`
	ApplicationACLs        IPRuleList              `json:"applicationACLs,omitempty"`
	NetworkACLs            IPRuleList              `json:"networkACLs,omitempty"`
	DNSACLs                DNSRuleList             `json:"dnsACLs,omitempty"`
	Identity               []string                `json:"identity,omitempty"`
	Annotations            []string                `json:"annotations,omitempty"`
	CompressedTags         []string                `json:"compressedtags,omitempty"`
	TransmitterRules       TagSelectorList         `json:"transmitterRules,omitempty"`
	ReceiverRules          TagSelectorList         `json:"receiverRules,omitempty"`
	IPs                    ExtendedMap             `json:"IPs,omitempty"`
	ServicesListeningPort  int                     `json:"servicesListeningPort,omitempty"`
	DNSProxyPort           int                     `json:"dnsProxyPort,omitempty"`
	ExposedServices        ApplicationServicesList `json:"exposedServices,omitempty"`
	DependentServices      ApplicationServicesList `json:"dependentServices,omitempty"`
	ServicesCertificate    string                  `json:"servicesCertificate,omitempty"`
	ServicesPrivateKey     string                  `json:"servicesPrivateKey,omitempty"`
	ServicesCA             string                  `json:"servicesCA,omitempty"`
	Scopes                 []string                `json:"scopes,omitempty"`
	EnforcerType           EnforcerType            `json:"enforcerTypes,omitempty"`
	AppDefaultPolicyAction ActionType              `json:"appDefaultPolicyAction,omitempty"`
	NetDefaultPolicyAction ActionType              `json:"netDefaultPolicyAction,omitempty"`
}

// ToPrivatePolicy converts the object to a private object.
func (p *PUPolicyPublic) ToPrivatePolicy(ctx context.Context, convert bool) (*PUPolicy, error) {
	var err error

	exposedServices := ApplicationServicesList{}
	for _, e := range p.ExposedServices {
		if convert {
			e.UserAuthorizationHandler, err = usertokens.NewVerifier(ctx, e.UserAuthorizationHandler)
			if err != nil {
				return nil, fmt.Errorf("unable to initialize user authorization handler for service: %s - error %s", e.ID, err)
			}
		}
		exposedServices = append(exposedServices, e)
	}

	return &PUPolicy{
		managementID:           p.ManagementID,
		managementNamespace:    p.ManagementNamespace,
		triremeAction:          p.TriremeAction,
		applicationACLs:        p.ApplicationACLs,
		networkACLs:            p.NetworkACLs.Copy(),
		DNSACLs:                p.DNSACLs.Copy(),
		transmitterRules:       p.TransmitterRules.Copy(),
		receiverRules:          p.ReceiverRules.Copy(),
		annotations:            NewTagStoreFromSlice(p.Annotations),
		compressedTags:         NewTagStoreFromSlice(p.CompressedTags),
		identity:               NewTagStoreFromSlice(p.Identity),
		ips:                    p.IPs.Copy(),
		servicesListeningPort:  p.ServicesListeningPort,
		dnsProxyPort:           p.DNSProxyPort,
		exposedServices:        exposedServices,
		dependentServices:      p.DependentServices,
		scopes:                 p.Scopes,
		enforcerType:           p.EnforcerType,
		servicesCA:             p.ServicesCA,
		servicesCertificate:    p.ServicesCertificate,
		servicesPrivateKey:     p.ServicesPrivateKey,
		appDefaultPolicyAction: p.AppDefaultPolicyAction,
		netDefaultPolicyAction: p.NetDefaultPolicyAction,
	}, nil
}
