package lookup

import (
	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/policy"
)

// ForwardingPolicy is an instance of the forwarding policy
type ForwardingPolicy struct {
	tags    []policy.KeyValueOperator
	count   int
	index   int
	actions interface{}
}

//PolicyDB is the structure of a policy
type PolicyDB struct {
	// rules    []policy
	numberOfPolicies int
	equalMapTable    map[string]map[string][]*ForwardingPolicy
	notEqualMapTable map[string]map[string][]*ForwardingPolicy
	starTable        map[string][]*ForwardingPolicy
	notStarTable     map[string][]*ForwardingPolicy
}

//NewPolicyDB creates a new PolicyDB for efficient search of policies
func NewPolicyDB() (m *PolicyDB) {

	m = &PolicyDB{
		numberOfPolicies: 0,
		equalMapTable:    map[string]map[string][]*ForwardingPolicy{},
		notEqualMapTable: map[string]map[string][]*ForwardingPolicy{},
		starTable:        map[string][]*ForwardingPolicy{},
		notStarTable:     map[string][]*ForwardingPolicy{},
	}

	return m
}

//AddPolicy adds a policy to the database
func (m *PolicyDB) AddPolicy(selector policy.TagSelector) (policyID int) {

	// Create a new policy object
	e := ForwardingPolicy{
		count:   0,
		tags:    selector.Clause,
		actions: selector.Action,
	}

	// For each tag of the incoming policy add a mapping between the map tables
	// and the structure that represents the policy
	for _, keyValueOp := range selector.Clause {

		switch keyValueOp.Operator {

		case policy.KeyExists:
			m.starTable[keyValueOp.Key] = append(m.starTable[keyValueOp.Key], &e)
			e.count++

		case policy.KeyNotExists:
			m.notStarTable[keyValueOp.Key] = append(m.notStarTable[keyValueOp.Key], &e)

		case policy.Equal:
			if _, ok := m.equalMapTable[keyValueOp.Key]; !ok {
				m.equalMapTable[keyValueOp.Key] = map[string][]*ForwardingPolicy{}
			}
			for _, v := range keyValueOp.Value {
				m.equalMapTable[keyValueOp.Key][v] = append(m.equalMapTable[keyValueOp.Key][v], &e)
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

//Search searches for a set of tags in the database to find a policy match
func (m *PolicyDB) Search(tags policy.TagsMap) (int, interface{}) {

	count := make([]int, m.numberOfPolicies+1)

	skip := make([]bool, m.numberOfPolicies+1)

	// Disable all policies that fail the not key exists
	for k := range tags {
		for _, policy := range m.notStarTable[k] {
			skip[policy.index] = true
		}
	}

	// Go through the list of tags
	for k, v := range tags {

		// Search for matches of k=*
		if index, action := searchInMapTabe(m.starTable[k], count, skip); index >= 0 {
			return index, action
		}

		// Search for matches of k=v
		if index, action := searchInMapTabe(m.equalMapTable[k][v], count, skip); index >= 0 {
			return index, action
		}

		// Parse all of the policies that have a key that matches the incoming tag key
		// and a not equal operator and that has a not match rule
		for value, policies := range m.notEqualMapTable[k] {
			if v == value {
				continue
			}

			if index, action := searchInMapTabe(policies, count, skip); index >= 0 {
				return index, action
			}
		}
	}
	return -1, nil
}

func searchInMapTabe(table []*ForwardingPolicy, count []int, skip []bool) (int, interface{}) {
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

	log.WithFields(log.Fields{
		"package": "lookup",
	}).Debug("Print Policy DB - equal table")

	for key, values := range m.equalMapTable {
		for value, policies := range values {
			log.WithFields(log.Fields{
				"package":  "lookup",
				"policies": policies,
				"key":      key,
				"value":    value,
			}).Debug("Print Policy DB")
		}
	}

	log.WithFields(log.Fields{
		"package": "lookup",
	}).Debug("Print Policy DB - not equal table")

	for key, values := range m.notEqualMapTable {
		for value, policies := range values {
			log.WithFields(log.Fields{
				"package":  "lookup",
				"policies": policies,
				"key":      key,
				"value":    value,
			}).Debug("Print Policy DB")
		}
	}

}
