package policy

import "strings"

// This file defines types and accessor methods for these types

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
	Accept FlowAction = 0x1
	// Reject is the reject  action
	Reject FlowAction = 0x2
	// Log intstructs the data to log informat
	Log FlowAction = 0x4
	// Encrypt instructs data to be encrypted
	Encrypt FlowAction = 0x8
)

const (
	// DefaultNamespace is the default namespace for applying policy
	DefaultNamespace = "bridge"
)

// PUAction defines the action types that applies for a specific PU as a whole.
type PUAction int

const (
	// AllowAll allows everything for the specific PU.
	AllowAll = 0x1
	// Police filters on the PU based on the PolicyRules.
	Police = 0x2
)

// IPRule holds IP rules to external services
type IPRule struct {
	Address  string
	Port     string
	Protocol string
	Action   FlowAction
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

// TagStore stores the tags - it allows duplicate key values
type TagStore []string

// NewTagStore creates a new TagStore
func NewTagStore() TagStore {
	return TagStore{}
}

// GetSlice returns the tagstore as a slice
func (t TagStore) GetSlice() []string {
	return t
}

// Copy copies an ExtendedMap
func (t TagStore) Copy() TagStore {

	c := make(TagStore, len(t))

	copy(c, t)

	return c
}

// Get does a lookup in the list of tags
func (t TagStore) Get(key string) (string, bool) {

	for _, kv := range t {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			return "", false
		}
		if key == parts[0] {
			return parts[1], true
		}
	}

	return "", false
}

// AppendKeyValue appends a key and value to the tag store
func (t TagStore) AppendKeyValue(key, value string) {
	t = append(t, key+"="+value)
}

// AppendTag appends a tag to the store
func (t TagStore) AppendTag(tag string) {
	t = append(t, tag)
}
