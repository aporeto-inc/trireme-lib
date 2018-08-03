package lookup

import (
	"fmt"
	"sort"

	"go.uber.org/zap"

	"go.aporeto.io/trireme-lib/policy"
)

// ForwardingPolicy is an instance of the forwarding policy
type ForwardingPolicy struct {
	tags    []policy.KeyValueOperator
	count   int
	index   int
	actions interface{}
}

// intList is a list of integeres
type intList []int

//PolicyDB is the structure of a policy
type PolicyDB struct {
	// rules    []policy
	numberOfPolicies       int
	equalPrefixes          map[string]intList
	equalMapTable          map[string]map[string][]*ForwardingPolicy
	equalIDMapTable        map[string][]*ForwardingPolicy
	notEqualMapTable       map[string]map[string][]*ForwardingPolicy
	notStarTable           map[string][]*ForwardingPolicy
	defaultNotExistsPolicy *ForwardingPolicy
}

//NewPolicyDB creates a new PolicyDB for efficient search of policies
func NewPolicyDB() (m *PolicyDB) {

	m = &PolicyDB{
		numberOfPolicies:       0,
		equalPrefixes:          map[string]intList{},
		equalMapTable:          map[string]map[string][]*ForwardingPolicy{},
		equalIDMapTable:        map[string][]*ForwardingPolicy{},
		notEqualMapTable:       map[string]map[string][]*ForwardingPolicy{},
		notStarTable:           map[string][]*ForwardingPolicy{},
		defaultNotExistsPolicy: nil,
	}

	return m
}

func (array intList) sortedInsert(value int) intList {
	l := len(array)
	if l == 0 {
		array = append(array, value)
		return array
	}

	i := sort.Search(l, func(i int) bool {
		return array[i] <= value
	})

	if i == 0 { // new value is the largest
		array = append([]int{value}, array...)
		return array
	}

	if i == l-1 { // new value is the smallest
		array = append(array, value)
		return array
	}

	inserted := append(array[0:i], value)

	return append(inserted, array[i:]...)

}

//AddPolicy adds a policy to the database
func (m *PolicyDB) AddPolicy(selector policy.TagSelector) (policyID int) {

	// Create a new policy object
	e := ForwardingPolicy{
		count:   0,
		tags:    selector.Clause,
		actions: selector.Policy,
	}

	// For each tag of the incoming policy add a mapping between the map tables
	// and the structure that represents the policy
	for _, keyValueOp := range selector.Clause {

		switch keyValueOp.Operator {

		case policy.KeyExists:
			m.equalPrefixes[keyValueOp.Key] = m.equalPrefixes[keyValueOp.Key].sortedInsert(0)
			if _, ok := m.equalMapTable[keyValueOp.Key]; !ok {
				m.equalMapTable[keyValueOp.Key] = map[string][]*ForwardingPolicy{}
			}
			m.equalMapTable[keyValueOp.Key][""] = append(m.equalMapTable[keyValueOp.Key][""], &e)
			e.count++

		case policy.KeyNotExists:
			m.notStarTable[keyValueOp.Key] = append(m.notStarTable[keyValueOp.Key], &e)
			if len(selector.Clause) == 1 {
				m.defaultNotExistsPolicy = &e
			}

		case policy.Equal:
			if _, ok := m.equalMapTable[keyValueOp.Key]; !ok {
				m.equalMapTable[keyValueOp.Key] = map[string][]*ForwardingPolicy{}
			}
			for _, v := range keyValueOp.Value {
				if end := len(v) - 1; v[end] == '*' {
					m.equalPrefixes[keyValueOp.Key] = m.equalPrefixes[keyValueOp.Key].sortedInsert(end)
					m.equalMapTable[keyValueOp.Key][v[:end]] = append(m.equalMapTable[keyValueOp.Key][v[:end]], &e)
				} else {
					m.equalMapTable[keyValueOp.Key][v] = append(m.equalMapTable[keyValueOp.Key][v], &e)
				}
			}
			if keyValueOp.ID != "" {
				if _, ok := m.equalIDMapTable[keyValueOp.ID]; !ok {
					m.equalIDMapTable[keyValueOp.ID] = []*ForwardingPolicy{}
				}
				m.equalIDMapTable[keyValueOp.ID] = append(m.equalIDMapTable[keyValueOp.ID], &e)
			}
			e.count++

		default: // policy.NotEqual
			if _, ok := m.notEqualMapTable[keyValueOp.Key]; !ok {
				m.notEqualMapTable[keyValueOp.Key] = map[string][]*ForwardingPolicy{}
			}
			for _, v := range keyValueOp.Value {
				m.notEqualMapTable[keyValueOp.Key][v] = append(m.notEqualMapTable[keyValueOp.Key][v], &e)
				e.count++
			}
		}
	}

	// Increase the number of policies
	m.numberOfPolicies++

	// Give the policy an index
	e.index = m.numberOfPolicies

	// Return the ID
	return e.index

}

// Custom implementation for splitting strings. Gives significant performance
// improvement. Do not allocate new strings
func (m *PolicyDB) tagSplit(tag string, k *string, v *string) error {
	l := len(tag)
	if l < 3 {
		return fmt.Errorf("Invalid tag: invalid length '%s'", tag)
	}

	if tag[0] == '=' {
		return fmt.Errorf("Invalid tag: missing key '%s'", tag)
	}

	for i := 0; i < l; i++ {
		if tag[i] == '=' {
			if i+1 >= l {
				return fmt.Errorf("Invalid tag: missing value '%s'", tag)
			}
			*k = tag[:i]
			*v = tag[i+1:]
			return nil
		}
	}

	return fmt.Errorf("Invalid tag: missing equal symbol '%s'", tag)
}

// Search searches for a set of tags in the database to find a policy match
func (m *PolicyDB) Search(tags *policy.TagStore) (int, interface{}) {

	count := make([]int, m.numberOfPolicies+1)

	skip := make([]bool, m.numberOfPolicies+1)

	// Disable all policies that fail the not key exists
	copiedTags := tags.GetSlice()
	var k, v string

	for _, t := range copiedTags {
		if err := m.tagSplit(t, &k, &v); err != nil {
			continue
		}
		for _, policy := range m.notStarTable[k] {
			skip[policy.index] = true
		}
	}

	// Go through the list of tags
	for _, t := range copiedTags {

		if err := m.tagSplit(t, &k, &v); err != nil {
			// Search for matches of t (tag id)
			if index, action := searchInMapTable(m.equalIDMapTable[t], count, skip); index >= 0 {
				return index, action
			}
			continue
		}

		// Search for matches of k=v
		if index, action := searchInMapTable(m.equalMapTable[k][v], count, skip); index >= 0 {
			return index, action
		}

		// Search for matches in prefixes
		for _, i := range m.equalPrefixes[k] {
			if i <= len(v) {
				if index, action := searchInMapTable(m.equalMapTable[k][v[:i]], count, skip); index >= 0 {
					return index, action
				}
			}
		}

		// Parse all of the policies that have a key that matches the incoming tag key
		// and a not equal operator and that has a not match rule
		for value, policies := range m.notEqualMapTable[k] {
			if v == value {
				continue
			}

			if index, action := searchInMapTable(policies, count, skip); index >= 0 {
				return index, action
			}
		}
	}

	if m.defaultNotExistsPolicy != nil && !skip[m.defaultNotExistsPolicy.index] {
		return m.defaultNotExistsPolicy.index, m.defaultNotExistsPolicy.actions
	}

	return -1, nil
}

func searchInMapTable(table []*ForwardingPolicy, count []int, skip []bool) (int, interface{}) {
	for _, policy := range table {

		// Skip the policy if we have marked it
		if skip[policy.index] {
			continue
		}

		// Since a policy is hit, the count of remaining tags is reduced by one
		count[policy.index]++

		// If all tags of the policy have been hit, there is a match
		if count[policy.index] == policy.count {
			return policy.index, policy.actions
		}

	}

	return -1, nil
}

// PrintPolicyDB is a debugging function to dump the map
func (m *PolicyDB) PrintPolicyDB() {

	zap.L().Debug("Print Policy DB: equal table")

	for key, values := range m.equalMapTable {
		for value, policies := range values {
			zap.L().Debug("Print Policy DB",
				zap.String("policies", fmt.Sprintf("%#v", policies)),
				zap.String("key", key),
				zap.String("value", value),
			)
		}
	}

	zap.L().Debug("Print Policy DB: equal id table")

	for key, values := range m.equalIDMapTable {
		for _, policies := range values {
			zap.L().Debug("Print Policy DB",
				zap.String("policies", fmt.Sprintf("%#v", policies)),
				zap.String("key", key),
			)
		}
	}

	zap.L().Debug("Print Policy DB - not equal table")

	for key, values := range m.notEqualMapTable {
		for value, policies := range values {
			zap.L().Debug("Print Policy DB",
				zap.String("policies", fmt.Sprintf("%#v", policies)),
				zap.String("key", key),
				zap.String("value", value),
			)
		}
	}

}
