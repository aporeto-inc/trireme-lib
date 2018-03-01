package policy

import (
	"sync"
)

// PUPolicy captures all policy information related ot the container
type PUPolicy struct {

	// ManagementID is provided for the policy implementations as a means of
	// holding a policy identifier related to the implementation.
	managementID string
	// triremeAction defines what level of policy should be applied to that container.
	triremeAction PUAction
	// applicationACLs is the list of ACLs to be applied when the container talks
	// to IP Addresses outside the data center
	applicationACLs IPRuleList
	// networkACLs is the list of ACLs to be applied from IP Addresses outside
	// the data center
	networkACLs IPRuleList
	// identity is the set of key value pairs that must be send over the wire.
	identity *TagStore
	// annotations are key/value pairs  that should be used for accounting reasons
	annotations *TagStore
	// transmitterRules is the set of rules that implement the label matching at the Transmitter
	transmitterRules TagSelectorList
	// teceiverRules is the set of rules that implement matching at the Receiver
	receiverRules TagSelectorList
	// ips is the set of IP addresses and namespaces that the policy must be applied to
	ips ExtendedMap
	// triremeNetworks is the list of networks that Authorization must be enforced
	triremeNetworks []string
	// excludedNetworks a list of networks that must be excluded
	excludedNetworks []string
	// ProxiedServices string format ip:port
	proxiedServices *ProxiedServicesInfo
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
	action PUAction,
	appACLs IPRuleList,
	netACLs IPRuleList,
	txtags TagSelectorList,
	rxtags TagSelectorList,
	identity *TagStore,
	annotations *TagStore,
	ips ExtendedMap,
	triremeNetworks []string,
	excludedNetworks []string,
	proxiedServices *ProxiedServicesInfo,
	exposedServices ApplicationServicesList,
	dependentServices ApplicationServicesList,
	scopes []string,
) *PUPolicy {

	if appACLs == nil {
		appACLs = IPRuleList{}
	}
	if netACLs == nil {
		netACLs = IPRuleList{}
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

	if ips == nil {
		ips = ExtendedMap{}
	}

	if proxiedServices == nil {
		proxiedServices = &ProxiedServicesInfo{}
	}

	if exposedServices == nil {
		exposedServices = ApplicationServicesList{}
	}

	if dependentServices == nil {
		dependentServices = ApplicationServicesList{}
	}

	return &PUPolicy{
		managementID:      id,
		triremeAction:     action,
		applicationACLs:   appACLs,
		networkACLs:       netACLs,
		transmitterRules:  txtags,
		receiverRules:     rxtags,
		identity:          identity,
		annotations:       annotations,
		ips:               ips,
		triremeNetworks:   triremeNetworks,
		excludedNetworks:  excludedNetworks,
		proxiedServices:   proxiedServices,
		exposedServices:   exposedServices,
		dependentServices: dependentServices,
		scopes:            scopes,
	}
}

// NewPUPolicyWithDefaults sets up a PU policy with defaults
func NewPUPolicyWithDefaults() *PUPolicy {
	return NewPUPolicy("", AllowAll, nil, nil, nil, nil, nil, nil, nil, []string{}, []string{}, &ProxiedServicesInfo{}, nil, nil, []string{})
}

// Clone returns a copy of the policy
func (p *PUPolicy) Clone() *PUPolicy {
	p.Lock()
	defer p.Unlock()

	np := NewPUPolicy(
		p.managementID,
		p.triremeAction,
		p.applicationACLs.Copy(),
		p.networkACLs.Copy(),
		p.transmitterRules.Copy(),
		p.receiverRules.Copy(),
		p.identity.Copy(),
		p.annotations.Copy(),
		p.ips.Copy(),
		p.triremeNetworks,
		p.excludedNetworks,
		p.proxiedServices,
		p.exposedServices,
		p.dependentServices,
		p.scopes,
	)

	return np
}

// ManagementID returns the management ID
func (p *PUPolicy) ManagementID() string {
	p.Lock()
	defer p.Unlock()

	return p.managementID
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

// TriremeNetworks  returns the list of networks that Trireme must be applied
func (p *PUPolicy) TriremeNetworks() []string {
	p.Lock()
	defer p.Unlock()

	return p.triremeNetworks
}

// ProxiedServices returns the list of networks that Trireme must be applied
func (p *PUPolicy) ProxiedServices() *ProxiedServicesInfo {
	p.Lock()
	defer p.Unlock()

	return p.proxiedServices
}

// ExposedServices returns the exposed services
func (p *PUPolicy) ExposedServices() ApplicationServicesList {
	p.Lock()
	defer p.Unlock()

	return p.exposedServices
}

// DependentServices returns the external services.
func (p *PUPolicy) DependentServices() ApplicationServicesList {
	p.Lock()
	defer p.Unlock()

	return p.dependentServices
}

// UpdateTriremeNetworks updates the set of networks for trireme
func (p *PUPolicy) UpdateTriremeNetworks(networks []string) {
	p.Lock()
	defer p.Unlock()

	p.triremeNetworks = make([]string, len(networks))

	copy(p.triremeNetworks, networks)

}

// ExcludedNetworks returns the list of excluded networks.
func (p *PUPolicy) ExcludedNetworks() []string {
	p.Lock()
	defer p.Unlock()

	return p.excludedNetworks
}

// UpdateExcludedNetworks updates the list of excluded networks.
func (p *PUPolicy) UpdateExcludedNetworks(networks []string) {
	p.Lock()
	defer p.Unlock()

	p.excludedNetworks = make([]string, len(networks))

	copy(p.excludedNetworks, networks)
}

// UpdateServiceCertificates updates the certificate and private key of the policy
func (p *PUPolicy) UpdateServiceCertificates(cert, key, caPool string) {
	p.Lock()
	defer p.Unlock()

	p.servicesCertificate = cert
	p.servicesPrivateKey = key
	p.servicesCA = caPool
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
