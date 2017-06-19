package policy

import "sync"

// PUPolicy captures all policy information related ot the container
type PUPolicy struct {
	//puPolicyMutex is a mutex to prevent access to same policy object from multiple threads
	puPolicyMutex *sync.Mutex
	// ManagementID is provided for the policy implementations as a means of
	// holding a policy identifier related to the implementation
	ManagementID string
	//TriremeAction defines what level of policy should be applied to that container.
	TriremeAction PUAction
	// applicationACLs is the list of ACLs to be applied when the container talks
	// to IP Addresses outside the data center
	applicationACLs *IPRuleList
	// networkACLs is the list of ACLs to be applied from IP Addresses outside
	// the data center
	networkACLs *IPRuleList
	// identity is the set of key value pairs that must be send over the wire.
	identity *TagsMap
	// annotations are key/value pairs  that should be used for accounting reasons
	annotations *TagsMap
	// transmitterRules is the set of rules that implement the label matching at the Transmitter
	transmitterRules *TagSelectorList
	// teceiverRules is the set of rules that implement matching at the Receiver
	receiverRules *TagSelectorList
	// ips is the set of IP addresses and namespaces that the policy must be applied to
	ips *IPMap
	// triremeNetworks is the list of networks that Authorization must be enforced
	triremeNetworks []string
	// excludedNetworks a list of networks that must be excluded
	excludedNetworks []string
	// Extensions is an interface to a data structure that allows the policy supervisor
	// to pass additional instructions to a plugin. Plugin and policy must be
	// coordinated to implement the interface
	Extensions interface{}
}

// NewPUPolicy generates a new ContainerPolicyInfo
// appACLs are the ACLs for packet coming from the Application/PU to the Network.
// netACLs are the ACLs for packet coming from the Network to the Application/PU.
func NewPUPolicy(
	id string,
	action PUAction,
	appACLs,
	netACLs *IPRuleList,
	txtags, rxtags *TagSelectorList,
	identity, annotations *TagsMap,
	ips *IPMap,
	triremeNetworks []string,
	excludedNetworks []string,
	e interface{}) *PUPolicy {

	if appACLs == nil {
		appACLs = NewIPRuleList(nil)
	}
	if netACLs == nil {
		netACLs = NewIPRuleList(nil)
	}
	if txtags == nil {
		txtags = NewTagSelectorList(nil)
	}
	if rxtags == nil {
		rxtags = NewTagSelectorList(nil)
	}
	if identity == nil {
		identity = NewTagsMap(nil)
	}
	if annotations == nil {
		annotations = NewTagsMap(nil)
	}
	if ips == nil {
		ips = NewIPMap(nil)
	}
	return &PUPolicy{
		puPolicyMutex:    &sync.Mutex{},
		ManagementID:     id,
		TriremeAction:    action,
		applicationACLs:  appACLs,
		networkACLs:      netACLs,
		transmitterRules: txtags,
		receiverRules:    rxtags,
		identity:         identity,
		annotations:      annotations,
		ips:              ips,
		triremeNetworks:  triremeNetworks,
		excludedNetworks: excludedNetworks,
		Extensions:       e,
	}
}

// NewPUPolicyWithDefaults sets up a PU policy with defaults
func NewPUPolicyWithDefaults() *PUPolicy {

	return NewPUPolicy("", AllowAll, nil, nil, nil, nil, nil, nil, nil, []string{}, []string{}, nil)
}

// Clone returns a copy of the policy
func (p *PUPolicy) Clone() *PUPolicy {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	np := NewPUPolicy(
		p.ManagementID,
		p.TriremeAction,
		p.applicationACLs.Clone(),
		p.networkACLs.Clone(),
		p.transmitterRules.Clone(),
		p.receiverRules.Clone(),
		p.identity.Clone(),
		p.annotations.Clone(),
		p.ips.Clone(),
		p.triremeNetworks,
		p.excludedNetworks,
		p.Extensions,
	)

	return np
}

// ApplicationACLs returns a copy of IPRuleList
func (p *PUPolicy) ApplicationACLs() *IPRuleList {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	return p.applicationACLs.Clone()
}

// NetworkACLs returns a copy of IPRuleList
func (p *PUPolicy) NetworkACLs() *IPRuleList {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	return p.networkACLs.Clone()
}

// ReceiverRules returns a copy of TagSelectorList
func (p *PUPolicy) ReceiverRules() *TagSelectorList {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	return p.receiverRules.Clone()
}

// AddReceiverRules adds a receiver rule
func (p *PUPolicy) AddReceiverRules(t *TagSelector) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	p.receiverRules.TagSelectors = append(p.receiverRules.TagSelectors, *t.Clone())
}

// TransmitterRules returns a copy of TagSelectorList
func (p *PUPolicy) TransmitterRules() *TagSelectorList {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	return p.transmitterRules.Clone()
}

// AddTransmitterRules adds a transmitter rule
func (p *PUPolicy) AddTransmitterRules(t *TagSelector) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	p.transmitterRules.TagSelectors = append(p.transmitterRules.TagSelectors, *t.Clone())
}

// Identity returns a copy of the Identity
func (p *PUPolicy) Identity() *TagsMap {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	return p.identity.Clone()
}

// Annotations returns a copy of the annotations
func (p *PUPolicy) Annotations() *TagsMap {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	return p.annotations.Clone()
}

// AddIdentityTag adds a policy tag
func (p *PUPolicy) AddIdentityTag(k, v string) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	p.identity.Tags[k] = v
}

// IPAddresses returns all the IP addresses for the processing unit
func (p *PUPolicy) IPAddresses() *IPMap {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	return p.ips.Clone()
}

// SetIPAddresses sets the IP addresses for the processing unit
func (p *PUPolicy) SetIPAddresses(l *IPMap) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	p.ips = l.Clone()
}

// DefaultIPAddress returns the default IP address for the processing unit
func (p *PUPolicy) DefaultIPAddress() (string, bool) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	if ip, ok := p.ips.IPs[DefaultNamespace]; ok {
		return ip, true
	}
	return "0.0.0.0/0", false
}

// TriremeNetworks  returns the list of networks that Trireme must be applied
func (p *PUPolicy) TriremeNetworks() []string {
	return p.triremeNetworks
}

// UpdateTriremeNetworks updates the set of networks for trireme
func (p *PUPolicy) UpdateTriremeNetworks(networks []string) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	p.triremeNetworks = []string{}
	p.triremeNetworks = append(p.triremeNetworks, networks...)
}

// ExcludedNetworks returns the list of excluded networks.
func (p *PUPolicy) ExcludedNetworks() []string {
	return p.excludedNetworks
}

// UpdateExcludedNetworks updates the list of excluded networks.
func (p *PUPolicy) UpdateExcludedNetworks(networks []string) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	p.excludedNetworks = []string{}
	p.excludedNetworks = append(p.excludedNetworks, networks...)
}
