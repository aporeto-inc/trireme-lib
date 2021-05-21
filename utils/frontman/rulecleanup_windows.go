// +build windows

package frontman

import (
	"strings"
)

type ruleCleanup interface {
	mapIpsetToRule(ipsetName string, filterName, criteriaName string)
	deleteRulesForIpset(wrapDriver WrapDriver, ipsetName string) error
	deleteRuleForIpsetByPrefix(wrapDriver WrapDriver, prefix string) error
	deleteRuleFromIpsetMap(filterName, criteriaName string)
	getRulesForIpset(ipsetName string) []*filterRulePair
}

type ruleCleaner struct {
	ipsetToRule map[string][]*filterRulePair
}

type filterRulePair struct {
	filterName   string
	ruleCriteria string
}

func newRuleCleanup() ruleCleanup {
	return &ruleCleaner{
		ipsetToRule: make(map[string][]*filterRulePair),
	}
}

// We keep a map of ipset name to rules. This is a safeguard to ensure that rules are deleted.
// Normally, during policy update, rules and ipsets are deleted explicitly and all works well.
// There are some instances though (Discovery Mode) where criteria name strings use in deletion
// do not align with criteria name strings used during addition. This will result in rules
// stranded in our driver, which is really bad for multiple reasons.
// Since deletion of ipsets is more orderly than deletion of rules by criteria name, and since
// the rules that are subject to being stranded are all so far associated with an ephemeral ipset,
// we can use the deletion of an ipset to trigger a cleanup of all rules associated with it.

func (r *ruleCleaner) mapIpsetToRule(ipsetName string, filterName, criteriaName string) {
	r.ipsetToRule[ipsetName] = append(r.ipsetToRule[ipsetName], &filterRulePair{filterName: filterName, ruleCriteria: criteriaName})
}

func (r *ruleCleaner) deleteRulesForIpset(wrapDriver WrapDriver, ipsetName string) error {
	for _, frpair := range r.ipsetToRule[ipsetName] {
		// In recent changes, these rule are already gone, so don't log an error if this fails.
		wrapDriver.DeleteFilterCriteria(frpair.filterName, frpair.ruleCriteria) //nolint
	}
	delete(r.ipsetToRule, ipsetName)
	return nil
}

func (r *ruleCleaner) deleteRuleForIpsetByPrefix(wrapDriver WrapDriver, prefix string) error {

	ipsets, err := wrapDriver.ListIpsets()
	if err != nil {
		return err
	}
	for _, ipsetName := range ipsets {
		if strings.HasPrefix(ipsetName, prefix) {
			if err := r.deleteRulesForIpset(wrapDriver, ipsetName); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *ruleCleaner) deleteRuleFromIpsetMap(filterName, criteriaName string) {
	// quadratic for now, optimize later if we need to
	for ipsetName, frpairs := range r.ipsetToRule {
		for i, frpair := range frpairs {
			if frpair.filterName == filterName && frpair.ruleCriteria == criteriaName {
				// delete pair from slice
				frpairs[i] = frpairs[len(frpairs)-1]
				r.ipsetToRule[ipsetName] = frpairs[:len(frpairs)-1]
				// rule can be mapped from multiple ipsets, so continue our outer loop
				break
			}
		}
	}
}

func (r *ruleCleaner) getRulesForIpset(ipsetName string) []*filterRulePair {
	frpairs := r.ipsetToRule[ipsetName]
	result := make([]*filterRulePair, len(frpairs))
	copy(result, frpairs)
	return result
}
