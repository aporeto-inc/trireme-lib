package policy

import "sync"

// PUPolicy captures all policy information related ot the container
type PUPolicy struct {

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
	identity []string
	// annotations are key/value pairs  that should be used for logging reasons
	annotations []string
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

	sync.Mutex
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
	identity []string,
	annotations []string,
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
		identity = []string{}
	}
	if annotations == nil {
		annotations = []string{}
	}
	if ips == nil {
		ips = NewIPMap(nil)
	}
	return &PUPolicy{
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
	p.Lock()
	defer p.Unlock()

	np := NewPUPolicy(
		p.ManagementID,
		p.TriremeAction,
		p.applicationACLs.Clone(),
		p.networkACLs.Clone(),
		p.transmitterRules.Clone(),
		p.receiverRules.Clone(),
		p.identity,
		p.annotations,
		p.ips.Clone(),
		p.triremeNetworks,
		p.excludedNetworks,
		p.Extensions,
	)

	return np
}

// ApplicationACLs returns a copy of IPRuleList
func (p *PUPolicy) ApplicationACLs() *IPRuleList {
	p.Lock()
	defer p.Unlock()

	return p.applicationACLs.Clone()
}

// NetworkACLs returns a copy of IPRuleList
func (p *PUPolicy) NetworkACLs() *IPRuleList {
	p.Lock()
	defer p.Unlock()

	return p.networkACLs.Clone()
}

// ReceiverRules returns a copy of TagSelectorList
func (p *PUPolicy) ReceiverRules() *TagSelectorList {
	p.Lock()
	defer p.Unlock()

	return p.receiverRules.Clone()
}

// AddReceiverRules adds a receiver rule
func (p *PUPolicy) AddReceiverRules(t *TagSelector) {
	p.Lock()
	defer p.Unlock()

	p.receiverRules.TagSelectors = append(p.receiverRules.TagSelectors, *t.Clone())
}

// TransmitterRules returns a copy of TagSelectorList
func (p *PUPolicy) TransmitterRules() *TagSelectorList {
	p.Lock()
	defer p.Unlock()

	return p.transmitterRules.Clone()
}

// AddTransmitterRules adds a transmitter rule
func (p *PUPolicy) AddTransmitterRules(t *TagSelector) {
	p.Lock()
	defer p.Unlock()

	p.transmitterRules.TagSelectors = append(p.transmitterRules.TagSelectors, *t.Clone())
}

// Identity returns a copy of the Identity
func (p *PUPolicy) Identity() []string {
	p.Lock()
	defer p.Unlock()

	return append([]string(nil), p.identity...)
}

// Annotations returns a copy of the annotations
func (p *PUPolicy) Annotations() []string {
	p.Lock()
	defer p.Unlock()

	return append([]string(nil), p.annotations...)
}

// AddIdentityTag adds a policy tag
func (p *PUPolicy) AddIdentityTag(tag string) {
	p.Lock()
	defer p.Unlock()

	p.identity = append(p.identity, tag)
}

// IPAddresses returns all the IP addresses for the processing unit
func (p *PUPolicy) IPAddresses() *IPMap {
	p.Lock()
	defer p.Unlock()

	return p.ips.Clone()
}

// SetIPAddresses sets the IP addresses for the processing unit
func (p *PUPolicy) SetIPAddresses(l *IPMap) {
	p.Lock()
	defer p.Unlock()

	p.ips = l.Clone()
}

// DefaultIPAddress returns the default IP address for the processing unit
func (p *PUPolicy) DefaultIPAddress() (string, bool) {
	p.Lock()
	defer p.Unlock()

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
	p.Lock()
	defer p.Unlock()

	p.triremeNetworks = []string{}
	p.triremeNetworks = append(p.triremeNetworks, networks...)
}

// ExcludedNetworks returns the list of excluded networks.
func (p *PUPolicy) ExcludedNetworks() []string {
	return p.excludedNetworks
}

// UpdateExcludedNetworks updates the list of excluded networks.
func (p *PUPolicy) UpdateExcludedNetworks(networks []string) {
	p.Lock()
	defer p.Unlock()

	p.excludedNetworks = []string{}
	p.excludedNetworks = append(p.excludedNetworks, networks...)
}
