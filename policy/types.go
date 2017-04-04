package policy

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
type IPRuleList struct {
	Rules []IPRule
}

// NewIPRuleList returns a new IP rule list
func NewIPRuleList(rules []IPRule) *IPRuleList {
	rl := &IPRuleList{
		Rules: []IPRule{},
	}
	rl.Rules = append(rl.Rules, rules...)

	return rl
}

// Clone creates a clone of the IP rule list
func (l *IPRuleList) Clone() *IPRuleList {
	return NewIPRuleList(l.Rules)
}

// An IPMap is a map of Key:Values used for IP Addresses.
type IPMap struct {
	IPs map[string]string
}

// NewIPMap returns a new instance of IPMap
func NewIPMap(ips map[string]string) *IPMap {
	ipm := &IPMap{
		IPs: map[string]string{},
	}
	for k, v := range ips {
		ipm.IPs[k] = v
	}
	return ipm
}

// Clone returns a copy of the map
func (i *IPMap) Clone() *IPMap {
	return NewIPMap(i.IPs)
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
func NewTagsMap(tags map[string]string) *TagsMap {
	tm := &TagsMap{
		Tags: map[string]string{},
	}
	if tags != nil {
		for k, v := range tags {
			tm.Tags[k] = v
		}
	}
	return tm
}

// Clone returns a copy of the map
func (t *TagsMap) Clone() *TagsMap {
	return NewTagsMap(t.Tags)
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
func NewKeyValueOperator(k string, o Operator, kvos []string) *KeyValueOperator {
	kvo := &KeyValueOperator{
		Key:      k,
		Operator: o,
		Value:    []string{},
	}

	kvo.Value = append(kvo.Value, kvos...)

	return kvo
}

// Clone returns a copy of the KeyValueOperator
func (k *KeyValueOperator) Clone() *KeyValueOperator {
	return NewKeyValueOperator(k.Key, k.Operator, k.Value)
}

// TagSelector info describes a tag selector key Operator value
type TagSelector struct {
	Clause []KeyValueOperator
	Action FlowAction
}

// NewTagSelector return a new TagSelector
func NewTagSelector(clauses []KeyValueOperator, a FlowAction) *TagSelector {
	ts := &TagSelector{
		Clause: []KeyValueOperator{},
		Action: a,
	}
	for _, c := range clauses {
		ts.Clause = append(ts.Clause, *c.Clone())
	}
	return ts
}

// Clone returns a copy of the TagSelector
func (t *TagSelector) Clone() *TagSelector {
	return NewTagSelector(t.Clause, t.Action)
}

// TagSelectorList defines a list of TagSelector
type TagSelectorList struct {
	TagSelectors []TagSelector
}

// NewTagSelectorList return a new TagSelectorList
func NewTagSelectorList(tss []TagSelector) *TagSelectorList {
	tsl := &TagSelectorList{
		TagSelectors: []TagSelector{},
	}
	for _, ts := range tss {
		tsl.TagSelectors = append(tsl.TagSelectors, *ts.Clone())
	}
	return tsl
}

// Clone returns a copy of the TagSelectorList
func (t *TagSelectorList) Clone() *TagSelectorList {
	return NewTagSelectorList(t.TagSelectors)
}
