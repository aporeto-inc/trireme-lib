package policy

// The Policy package describes a generic interface for retrieving policies.
// Different implementations are possible for environments such as Kubernetes,
// Mesos or other custom environments. An implementation has to provide
// a method for retrieving policy based on the metadata associated with the container
// and deleting the policy when the container dies. It is up to the implementation
// to decide how to generate the policy.
// The package also defines the basic data structure for communicating policy
// information. The implementations are responsible for providing all the necessary
// data.

// IPRule holds ingress IP table rules to external services
type IPRule struct {
	Address  string
	Port     string
	Protocol string
}

// TagMap is a map of Key:Values used as tags.
type TagMap map[string]string

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

// TagSelector info describes a tag selector key Operator value
type TagSelector struct {
	Clause []KeyValueOperator
	Action FlowAction
}

// KeyValueOperator describes an individual matching rule
type KeyValueOperator struct {
	Key      string
	Value    []string
	Operator Operator
}

// PUPolicy captures all policy information related ot the container
type PUPolicy struct {
	// ManagementID is provided for the policy implementations as a means of
	// holding a policy identifier related to the implementation
	ManagementID string
	//TriremeAction defines what level of policy should be applied to that container.
	TriremeAction PUAction
	// IngressACLs is the list of ACLs to be applied when the container talks
	// to IP Addresses outside the data center
	IngressACLs []IPRule
	// EgressACLs is the list of ACLs to be applied from IP Addresses outside
	// the data center
	EgressACLs []IPRule
	// PolicyTags are the tags that will be sent on the wire and used for policing.
	PolicyTags TagMap
	// Rules is the set of rules that implement the label matching.
	Rules []TagSelector
	// Extensions is an interface to a data structure that allows the policy controller
	// to pass additional instructions to a plugin. Plugin and policy must be
	// coordinated to implement the interface
	Extensions interface{}
}

// PURuntime holds all data related to the status of the container run time
type PURuntime struct {
	// Pid holds the value of the first process of the container
	pid int
	// Name is the name of the container
	name string
	// IPAddress is the IP Address of the container
	iPAddresses map[string]string
	// Tags is a map of the metadata of the container
	tags TagMap
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
	ip, ok := r.iPAddresses["bridge"]
	return ip, ok
}

// IPAddresses returns all the IP addresses for the processing unit
func (r *PURuntime) IPAddresses() map[string]string {
	return r.iPAddresses
}

// SetIPAddresses sets up all the IP addresses for the processing unit
func (r *PURuntime) SetIPAddresses(ipa map[string]string) {
	r.iPAddresses = ipa
}

//Tag returns a specific tag for the processing unit
func (r *PURuntime) Tag(key string) (string, bool) {
	tag, ok := r.tags[key]
	return tag, ok
}

//Tags returns tags for the processing unit
func (r *PURuntime) Tags() TagMap {
	return r.tags
}

//SetTags sets tags for the processing unit
func (r *PURuntime) SetTags(tags TagMap) {
	r.tags = tags
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

// NewPUPolicy generates a new ContainerPolicyInfo
func NewPUPolicy() *PUPolicy {
	return &PUPolicy{
		IngressACLs: []IPRule{},
		EgressACLs:  []IPRule{},
		Rules:       []TagSelector{},
		PolicyTags:  map[string]string{},
	}
}

// NewPURuntime Generate a new RuntimeInfo
func NewPURuntime() *PURuntime {
	return &PURuntime{
		tags:        map[string]string{},
		iPAddresses: map[string]string{},
	}
}

// PUInfoFromPolicyAndRuntime generates a ContainerInfo Struct from an existing RuntimeInfo and PolicyInfo
func PUInfoFromPolicyAndRuntime(contextID string, policyInfo *PUPolicy, runtimeInfo *PURuntime) *PUInfo {
	return &PUInfo{
		ContextID: contextID,
		Policy:    policyInfo,
		Runtime:   runtimeInfo,
	}
}
