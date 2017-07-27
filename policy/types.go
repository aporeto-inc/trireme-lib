package policy

const (
	// DefaultNamespace is the default namespace for applying policy
	DefaultNamespace = "bridge"
)

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

// ActionType   is the action that can be applied to a flow.
type ActionType byte

// Accepted returns if the action mask contains the Accepted mask.
func (f ActionType) Accepted() bool {
	return f&Accept > 0
}

// Rejected returns if the action mask contains the Rejected mask.
func (f ActionType) Rejected() bool {
	return f&Reject > 0
}

// Encrypted returns if the action mask contains the Encrypted mask.
func (f ActionType) Encrypted() bool {
	return f&Encrypt > 0
}

// Logged returns if the action mask contains the Logged mask.
func (f ActionType) Logged() bool {
	return f&Log > 0
}

// ShortAcceptedString returns if the action if accepted of rejected as a short string.
func (f ActionType) ShortAcceptedString() string {
	if f.Accepted() && !f.Rejected() {
		return "a"
	}

	if !f.Accepted() && f.Rejected() {
		return "r"
	}
	return "p"
}

func (f ActionType) String() string {
	switch f {
	case Accept:
		return "accept"
	case Reject:
		return "reject"
	case Encrypt:
		return "encrypt"
	case Log:
		return "log"
	}

	return "unknown"
}

const (
	// Accept is the accept action
	Accept ActionType = 0x1
	// Reject is the reject  action
	Reject ActionType = 0x2
	// Encrypt instructs data to be encrypted
	Encrypt ActionType = 0x4
	// Log instructs the datapath to log the IP addresses
	Log ActionType = 0x8
)

// FlowPolicy captures the policy for a particular flow
type FlowPolicy struct {
	Action    ActionType
	ServiceID string
	PolicyID  string
}

// IPRule holds IP rules to external services
type IPRule struct {
	Address  string
	Port     string
	Protocol string
	Policy   *FlowPolicy
}

// IPRuleList is a list of IP rules
type IPRuleList []IPRule

// Copy creates a clone of the IP rule list
func (l IPRuleList) Copy() IPRuleList {
	list := make(IPRuleList, len(l))
	for i, v := range l {
		list[i] = v
	}
	return list
}

// KeyValueOperator describes an individual matching rule
type KeyValueOperator struct {
	Key      string
	Value    []string
	Operator Operator
}

// TagSelector info describes a tag selector key Operator value
type TagSelector struct {
	Clause []KeyValueOperator
	Policy *FlowPolicy
}

// TagSelectorList defines a list of TagSelectors
type TagSelectorList []TagSelector

// Copy  returns a copy of the TagSelectorList
func (t TagSelectorList) Copy() TagSelectorList {
	list := make(TagSelectorList, len(t))

	for i, v := range t {
		list[i] = v
	}

	return list
}

// ExtendedMap is a common map with additional functions
type ExtendedMap map[string]string

// Copy copies an ExtendedMap
func (s ExtendedMap) Copy() ExtendedMap {
	c := ExtendedMap{}
	for k, v := range s {
		c[k] = v
	}
	return c
}

// Get does a lookup in the map
func (s ExtendedMap) Get(key string) (string, bool) {
	value, ok := s[key]
	return value, ok
}
