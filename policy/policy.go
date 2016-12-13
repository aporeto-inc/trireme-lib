// Package policy describes a generic interface for retrieving policies.
// Different implementations are possible for environments such as Kubernetes,
// Mesos or other custom environments. An implementation has to provide
// a method for retrieving policy based on the metadata associated with the container
// and deleting the policy when the container dies. It is up to the implementation
// to decide how to generate the policy.
// The package also defines the basic data structure for communicating policy
// information. The implementations are responsible for providing all the necessary
// data.
package policy

import "sync"

// Operator defines the operation between your key and value.
type Operator string

const (
	// Equal is the equal operator
	Equal = "="
	// NotEqual is the not equal operator
	NotEqual = "=!"
	// KeyExists is the key=* operator
	KeyExists = "*"
	// KeyNotExists means that the key doesnt exist in the incoming tags
	KeyNotExists = "!*"
)

// FlowAction is the action that can be applied to a flow.
type FlowAction int

const (
	// Accept is the accept action
	Accept = 0x1
	// Log intstructs the data to log informat
	Log = 0x2
	// Encrypt instructs data to be encrypted
	Encrypt = 0x4
)

// PUAction defines the action types that applies for a specific PU as a whole.
type PUAction int

const (
	// AllowAll allows everything for the specific PU.
	AllowAll = 0x1
	// Police filters on the PU based on the PolicyRules.
	Police = 0x2
)

// IPList stores a list of IPs
type IPList struct {
	IPs []string
}

// NewIPList returns a new IP list
func NewIPList() *IPList {
	return &IPList{
		IPs: []string{},
	}
}

// Clone creates a clone of the list
func (l *IPList) Clone() *IPList {
	ipl := NewIPList()
	for _, v := range l.IPs {
		ipl.IPs = append(ipl.IPs, v)
	}
	return ipl
}

// IPAtIndex returns the IP at a given index. Returns true if entry is valid
func (l *IPList) IPAtIndex(index int) (string, bool) {
	if len(l.IPs) > index {
		return l.IPs[index], true
	}
	return "", false
}

// IPRule holds IP rules to external services
type IPRule struct {
	Address  string
	Port     string
	Protocol string
}

// IPRuleList is a list of IP rules
type IPRuleList struct {
	Rules []IPRule
}

// NewIPRuleList returns a new IP rule list
func NewIPRuleList() *IPRuleList {
	return &IPRuleList{
		Rules: []IPRule{},
	}
}

// Clone creates a clone of the IP rule list
func (l *IPRuleList) Clone() *IPRuleList {
	rl := NewIPRuleList()
	for _, v := range l.Rules {
		rl.Rules = append(rl.Rules, v)
	}
	return rl
}

// An IPMap is a map of Key:Values used for IP Addresses.
type IPMap struct {
	IPs map[string]string
}

// NewIPMap returns a new instance of IPMap
func NewIPMap() *IPMap {
	return &IPMap{IPs: make(map[string]string)}
}

// Clone returns a copy of the map
func (i *IPMap) Clone() *IPMap {
	im := NewIPMap()
	for k, v := range i.IPs {
		im.IPs[k] = v
	}
	return im
}

// Add adds a key value pair
func (i *IPMap) Add(k, v string) {
	i.IPs[k] = v
}

// Get returns the value of a given key
func (i *IPMap) Get(k string) (string, bool) {
	v, ok := i.IPs[k]
	return v, ok
}

// A TagsMap is a map of Key:Values used as tags.
type TagsMap struct {
	Tags map[string]string
}

// NewTagsMap returns a new instance of TagsMap
func NewTagsMap() *TagsMap {
	return &TagsMap{Tags: make(map[string]string)}
}

// Clone returns a copy of the map
func (t *TagsMap) Clone() *TagsMap {
	tm := NewTagsMap()
	for k, v := range t.Tags {
		tm.Tags[k] = v
	}
	return tm
}

// Get returns the value of a given key
func (t *TagsMap) Get(k string) (string, bool) {
	v, ok := t.Tags[k]
	return v, ok
}

// Add adds a key value pair
func (t *TagsMap) Add(k, v string) {
	t.Tags[k] = v
}

// KeyValueOperator describes an individual matching rule
type KeyValueOperator struct {
	Key      string
	Value    []string
	Operator Operator
}

// NewKeyValueOperator returns an empty KeyValueOperator
func NewKeyValueOperator() *KeyValueOperator {
	return &KeyValueOperator{
		Value: make([]string, 0),
	}
}

// Clone returns a copy of the KeyValueOperator
func (k *KeyValueOperator) Clone() *KeyValueOperator {
	kvo := NewKeyValueOperator()
	kvo.Key = k.Key
	kvo.Operator = k.Operator
	for _, v := range k.Value {
		kvo.Value = append(kvo.Value, v)
	}
	return kvo
}

// TagSelector info describes a tag selector key Operator value
type TagSelector struct {
	Clause []KeyValueOperator
	Action FlowAction
}

// NewTagSelector return a new TagSelector
func NewTagSelector() *TagSelector {
	return &TagSelector{
		Clause: make([]KeyValueOperator, 0),
	}
}

// Clone returns a copy of the TagSelector
func (t *TagSelector) Clone() *TagSelector {
	ts := NewTagSelector()
	ts.Action = t.Action
	for _, c := range t.Clause {
		ts.Clause = append(ts.Clause, *c.Clone())
	}
	return ts
}

// TagSelectorList defines a list of TagSelector
type TagSelectorList struct {
	TagSelectors []TagSelector
}

// NewTagSelectorList return a new TagSelectorList
func NewTagSelectorList() *TagSelectorList {
	return &TagSelectorList{
		TagSelectors: make([]TagSelector, 0),
	}
}

// Clone returns a copy of the TagSelectorList
func (t *TagSelectorList) Clone() *TagSelectorList {
	tsl := NewTagSelectorList()
	for _, ts := range t.TagSelectors {
		tsl.TagSelectors = append(tsl.TagSelectors, *ts.Clone())
	}
	return tsl
}

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
func NewPUPolicy() *PUPolicy {
	return &PUPolicy{
		puPolicyMutex:    &sync.Mutex{},
		ingressACLs:      NewIPRuleList(),
		egressACLs:       NewIPRuleList(),
		transmitterRules: NewTagSelectorList(),
		receiverRules:    NewTagSelectorList(),
		policyTags:       NewTagsMap(),
		policyIPs:        NewIPList(),
	}
}

// Clone returns a copy of the policy
func (p *PUPolicy) Clone() *PUPolicy {
	p.puPolicyMutex.Lock()
	defer p.puPolicyMutex.Unlock()

	np := NewPUPolicy()
	np.puPolicyMutex = &sync.Mutex{}
	np.ManagementID = p.ManagementID
	np.TriremeAction = p.TriremeAction
	np.ingressACLs = p.ingressACLs.Clone()
	np.egressACLs = p.egressACLs.Clone()
	np.transmitterRules = p.transmitterRules.Clone()
	np.receiverRules = p.receiverRules.Clone()
	np.policyTags = p.policyTags.Clone()
	np.policyIPs = p.policyIPs.Clone()

	// TODO: Make this clonable
	np.Extensions = p.Extensions
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
	iPAddresses *IPMap
	// Tags is a map of the metadata of the container
	tags *TagsMap
}

// NewPURuntime Generate a new RuntimeInfo
func NewPURuntime() *PURuntime {
	return &PURuntime{
		puRuntimeMutex: &sync.Mutex{},
		tags:           NewTagsMap(),
		iPAddresses:    NewIPMap(),
	}
}

// Clone returns a copy of the policy
func (r *PURuntime) Clone() *PURuntime {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	np := NewPURuntime()
	np.puRuntimeMutex = &sync.Mutex{}
	np.tags = r.tags.Clone()
	np.iPAddresses = r.iPAddresses.Clone()
	return np
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

	ip, ok := r.iPAddresses.Get("bridge")
	return ip, ok
}

// IPAddresses returns all the IP addresses for the processing unit
func (r *PURuntime) IPAddresses() *IPMap {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	return r.iPAddresses.Clone()
}

// SetIPAddresses sets up all the IP addresses for the processing unit
func (r *PURuntime) SetIPAddresses(ipa *IPMap) {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	r.iPAddresses = ipa.Clone()
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
	policy := NewPUPolicy()
	runtime := NewPURuntime()
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
