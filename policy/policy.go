package policy

import (
	"encoding/json"
	"sync"
)

// PUPolicy captures all policy information related ot the container
type PUPolicy struct {
	//puPolicyMutex is a mutex to prevent access to same policy object from multiple threads
	puPolicyMutex *sync.Mutex
	// ManagementID is provided for the policy implementations as a means of
	// holding a policy identifier related to the implementation
	ManagementID string
	//TriremeAction defines what level of policy should be applied to that container.
	TriremeAction PUAction
	// IngressACLs is the list of ACLs to be applied when the container talks
	// to IP Addresses outside the data center
	ingressACLs *IPRuleList
	// EgressACLs is the list of ACLs to be applied from IP Addresses outside
	// the data center
	egressACLs *IPRuleList
	// PolicyTags are the tags that will be sent on the wire and used for policing.
	policyTags *TagsMap
	// PolicyIPs are the endpoint PU IP that we want to apply Trireme to. By default this would represent the same set of IPs as the Runtime would give you.
	policyIPs *IPList
	// TransmitterRules is the set of rules that implement the label matching at the Transmitter
	transmitterRules *TagSelectorList
	// ReceiverRules is the set of rules that implement matching at the Receiver
	receiverRules *TagSelectorList
	// Extensions is an interface to a data structure that allows the policy supervisor
	// to pass additional instructions to a plugin. Plugin and policy must be
	// coordinated to implement the interface
	Extensions interface{}
}

// NewPUPolicy generates a new ContainerPolicyInfo
func NewPUPolicy(id string, action PUAction, ingress, egress *IPRuleList, txtags, rxtags *TagSelectorList, ptags *TagsMap, ips *IPList, e interface{}) *PUPolicy {

	if ingress == nil {
		ingress = NewIPRuleList(nil)
	}
	if egress == nil {
		egress = NewIPRuleList(nil)
	}
	if txtags == nil {
		txtags = NewTagSelectorList(nil)
	}
	if rxtags == nil {
		rxtags = NewTagSelectorList(nil)
	}
	if ptags == nil {
		ptags = NewTagsMap(nil)
	}
	if ips == nil {
		ips = NewIPList(nil)
	}
	return &PUPolicy{
		puPolicyMutex:    &sync.Mutex{},
		ManagementID:     id,
		TriremeAction:    action,
		ingressACLs:      ingress,
		egressACLs:       egress,
		transmitterRules: txtags,
		receiverRules:    rxtags,
		policyTags:       ptags,
		policyIPs:        ips,
		Extensions:       e,
	}
}

// NewPUPolicyWithDefaults sets up a PU policy with defaults
func NewPUPolicyWithDefaults() *PUPolicy {

	return NewPUPolicy("", AllowAll, nil, nil, nil, nil, nil, nil, nil)
}

// Clone returns a copy of the policy
func (p *PUPolicy) Clone() *PUPolicy {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	np := NewPUPolicy(
		p.ManagementID,
		p.TriremeAction,
		p.ingressACLs.Clone(),
		p.egressACLs.Clone(),
		p.transmitterRules.Clone(),
		p.receiverRules.Clone(),
		p.policyTags.Clone(),
		p.policyIPs.Clone(),
		p.Extensions,
	)
	return np
}

// IngressACLs returns a copy of IPRuleList
func (p *PUPolicy) IngressACLs() *IPRuleList {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	return p.ingressACLs.Clone()
}

// SetIngressACLs adds ingress rules
func (p *PUPolicy) SetIngressACLs(r *IPRuleList) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	p.ingressACLs = r.Clone()
}

// EgressACLs returns a copy of IPRuleList
func (p *PUPolicy) EgressACLs() *IPRuleList {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	return p.egressACLs.Clone()
}

// SetEgressACLs adds ingress rules
func (p *PUPolicy) SetEgressACLs(r *IPRuleList) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	p.egressACLs = r.Clone()
}

// ReceiverRules returns a copy of TagSelectorList
func (p *PUPolicy) ReceiverRules() *TagSelectorList {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	return p.receiverRules.Clone()
}

// SetReceiverRules sets up receiver rules
func (p *PUPolicy) SetReceiverRules(t *TagSelectorList) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	p.receiverRules = t.Clone()
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

// SetTransmitterRules sets up receiver rules
func (p *PUPolicy) SetTransmitterRules(t *TagSelectorList) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	p.transmitterRules = t.Clone()
}

// AddTransmitterRules adds a transmitter rule
func (p *PUPolicy) AddTransmitterRules(t *TagSelector) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	p.transmitterRules.TagSelectors = append(p.transmitterRules.TagSelectors, *t.Clone())
}

// PolicyTags returns a copy of PolicyTag(s)
func (p *PUPolicy) PolicyTags() *TagsMap {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	return p.policyTags.Clone()
}

// SetPolicyTags sets up policy tags
func (p *PUPolicy) SetPolicyTags(t *TagsMap) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	p.policyTags = t.Clone()
}

// AddPolicyTag adds a policy tag
func (p *PUPolicy) AddPolicyTag(k, v string) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	p.policyTags.Tags[k] = v
}

// IPAddresses returns all the IP addresses for the processing unit
func (p *PUPolicy) IPAddresses() *IPList {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	return p.policyIPs.Clone()
}

// SetIPAddresses sets the IP addresses for the processing unit
func (p *PUPolicy) SetIPAddresses(l *IPList) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	p.policyIPs = l.Clone()
}

// DefaultIPAddress returns the default IP address for the processing unit
func (p *PUPolicy) DefaultIPAddress() (string, bool) {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	return p.policyIPs.IPAtIndex(0)
}

// PURuntime holds all data related to the status of the container run time
type PURuntime struct {
	//PURuntimeMutex is a mutex to prevent access to same runtime object from multiple threads
	puRuntimeMutex *sync.Mutex
	// Pid holds the value of the first process of the container
	pid int
	// Name is the name of the container
	name string
	// IPAddress is the IP Address of the container
	ips *IPMap
	// Tags is a map of the metadata of the container
	tags *TagsMap
}

// NewPURuntime Generate a new RuntimeInfo
func NewPURuntime(name string, pid int, tags *TagsMap, ips *IPMap) *PURuntime {

	t := tags
	if t == nil {
		t = NewTagsMap(nil)
	}
	i := ips
	if i == nil {
		i = NewIPMap(nil)
	}
	return &PURuntime{
		puRuntimeMutex: &sync.Mutex{},
		tags:           t,
		ips:            i,
	}
}

// NewPURuntimeWithDefaults sets up PURuntime with defaults
func NewPURuntimeWithDefaults() *PURuntime {

	return NewPURuntime("", 0, nil, nil)
}

// Clone returns a copy of the policy
func (r *PURuntime) Clone() *PURuntime {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	return NewPURuntime(r.name, r.pid, r.tags.Clone(), r.ips.Clone())
}

// PURuntimeJSON is a Json representation of PURuntime
type PURuntimeJSON struct {
	// Pid holds the value of the first process of the container
	Pid int
	// Name is the name of the container
	Name string
	// IPAddress is the IP Address of the container
	IPAddresses *IPMap
	// Tags is a map of the metadata of the container
	Tags *TagsMap
}

// MarshalJSON Marshals this struct.
func (r *PURuntime) MarshalJSON() ([]byte, error) {
	return json.Marshal(&PURuntimeJSON{
		Pid:         r.pid,
		Name:        r.name,
		IPAddresses: r.ips,
		Tags:        r.tags,
	})
}

// UnmarshalJSON Unmarshals this struct.
func (r *PURuntime) UnmarshalJSON(param []byte) error {
	a := &PURuntimeJSON{}
	json.Unmarshal(param, &a)
	r.pid = a.Pid
	r.name = a.Name
	r.ips = a.IPAddresses
	r.tags = a.Tags
	return nil
}

// Pid returns the PID
func (r *PURuntime) Pid() int {
	return r.pid
}

// SetPid sets the PID
func (r *PURuntime) SetPid(pid int) {
	r.pid = pid
}

// Name returns the PID
func (r *PURuntime) Name() string {
	return r.name
}

// SetName sets the Name
func (r *PURuntime) SetName(name string) {
	r.name = name
}

// DefaultIPAddress returns the default IP address for the processing unit
func (r *PURuntime) DefaultIPAddress() (string, bool) {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	ip, ok := r.ips.Get("bridge")
	return ip, ok
}

// IPAddresses returns all the IP addresses for the processing unit
func (r *PURuntime) IPAddresses() *IPMap {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	return r.ips.Clone()
}

// SetIPAddresses sets up all the IP addresses for the processing unit
func (r *PURuntime) SetIPAddresses(ipa *IPMap) {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	r.ips = ipa.Clone()
}

//Tag returns a specific tag for the processing unit
func (r *PURuntime) Tag(key string) (string, bool) {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	tag, ok := r.tags.Get(key)
	return tag, ok
}

//Tags returns tags for the processing unit
func (r *PURuntime) Tags() *TagsMap {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	return r.tags.Clone()
}

//SetTags sets tags for the processing unit
func (r *PURuntime) SetTags(tags *TagsMap) {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	r.tags = tags.Clone()
}

// PUInfo  captures all policy information related to a connection
type PUInfo struct {
	// ContextID is the ID of the container that the policy applies to
	ContextID string
	// Policy is an instantiation of the container policy
	Policy *PUPolicy
	// RunTime captures all data that are captured from the container
	Runtime *PURuntime
}

// NewPUInfo instantiates a new ContainerPolicy
func NewPUInfo(contextID string) *PUInfo {
	policy := NewPUPolicy("", AllowAll, nil, nil, nil, nil, nil, nil, nil)
	runtime := NewPURuntime("", 0, nil, nil)
	return PUInfoFromPolicyAndRuntime(contextID, policy, runtime)
}

// PUInfoFromPolicyAndRuntime generates a ContainerInfo Struct from an existing RuntimeInfo and PolicyInfo
func PUInfoFromPolicyAndRuntime(contextID string, policyInfo *PUPolicy, runtimeInfo *PURuntime) *PUInfo {
	return &PUInfo{
		ContextID: contextID,
		Policy:    policyInfo,
		Runtime:   runtimeInfo,
	}
}
