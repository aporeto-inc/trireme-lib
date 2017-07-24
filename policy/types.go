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

// FlowAction is the action that can be applied to a flow.
type FlowAction int

func (f FlowAction) String() string {
	switch f {
	case Accept:
		return "accept"
	case Reject:
		return "reject"
	case Encrypt:
		return "encrypt"
	}

	return "unknown"
}

const (
	// Accept is the accept action
	Accept FlowAction = 0x1
	// Reject is the reject  action
	Reject FlowAction = 0x2
	// Encrypt instructs data to be encrypted
	Encrypt FlowAction = 0x4
)

// IPRule holds IP rules to external services
type IPRule struct {
	Address   string
	Port      string
	Protocol  string
	Action    FlowAction
	Log       bool
	LogPrefix string
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
	Action FlowAction
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
