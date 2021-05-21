// +build windows

package frontman

import (
	"fmt"
	"strings"
	"testing"
)

const (
	ipset1  = "ipset-1"
	ipset2  = "ipset-2"
	ipset3  = "ipset-3"
	ipset4  = "ipset-4"
	ipset5  = "ipset-5"
	ipset6a = "ipset-6a"
	ipset6b = "ipset-6b"
	filter1 = "filter 1"
	filter2 = "filter 2"
	filter3 = "filter 3"
	filter4 = "filter 4"
)

var (
	rule1 = fmt.Sprintf("rule 1 for %s", ipset1)
	rule2 = fmt.Sprintf("rule 2 for %s and %s", ipset1, ipset2)
	rule3 = fmt.Sprintf("rule 3 for %s", ipset2)
	rule4 = fmt.Sprintf("rule 4 for %s", ipset3)
	rule5 = fmt.Sprintf("rule 5 for %s", ipset4)
	rule6 = fmt.Sprintf("rule 6 for %s and %s and two different filters", ipset4, ipset5)
	rule7 = fmt.Sprintf("rule 7 for %s and two different filters", ipset4)
	rule8 = fmt.Sprintf("rule 8 for %s", ipset6a)
	rule9 = fmt.Sprintf("rule 9 for %s", ipset6b)
)

type wrapperForTest struct {
	cleaner ruleCleanup
	ipsets  map[string]bool
	rules   map[string]map[string]bool
}

func (w *wrapperForTest) addRule(ipsetName, filterName, ruleCriteria string) {
	w.cleaner.mapIpsetToRule(ipsetName, filterName, ruleCriteria)
	w.ipsets[ipsetName] = true
	if _, ok := w.rules[filterName]; !ok {
		w.rules[filterName] = make(map[string]bool)
	}
	w.rules[filterName][ruleCriteria] = true
}

func (w *wrapperForTest) deleteIpset(ipsetName string) error {
	if err := w.cleaner.deleteRulesForIpset(w, ipsetName); err != nil {
		return err
	}
	delete(w.ipsets, ipsetName)
	return nil
}

func (w *wrapperForTest) deleteIpsetByPrefix(ipsetNamePrefix string) error {
	if err := w.cleaner.deleteRuleForIpsetByPrefix(w, ipsetNamePrefix); err != nil {
		return err
	}
	for ipsetName := range w.ipsets {
		if strings.HasPrefix(ipsetName, ipsetNamePrefix) {
			delete(w.ipsets, ipsetName)
		}
	}
	return nil
}

func (w *wrapperForTest) ruleExists(filterName, ruleCriteria string) bool {
	_, ok := w.rules[filterName][ruleCriteria]
	return ok
}

func (w *wrapperForTest) deleteRule(filterName, ruleCriteria string) {
	w.cleaner.deleteRuleFromIpsetMap(filterName, ruleCriteria)
	delete(w.rules[filterName], ruleCriteria)
}

func Test_ruleCleaner(t *testing.T) {

	wrapper := &wrapperForTest{
		ipsets:  make(map[string]bool),
		rules:   make(map[string]map[string]bool),
		cleaner: newRuleCleanup(),
	}

	// Add some ipsets and rules
	wrapper.addRule(ipset1, filter1, rule1)
	wrapper.addRule(ipset1, filter2, rule2)
	wrapper.addRule(ipset2, filter2, rule2)
	wrapper.addRule(ipset2, filter1, rule3)
	wrapper.addRule(ipset2, filter2, rule3)
	wrapper.addRule(ipset3, filter3, rule4)
	wrapper.addRule(ipset1, filter3, rule1)
	wrapper.addRule(ipset1, filter4, rule1)
	wrapper.addRule(ipset4, filter1, rule5)
	wrapper.addRule(ipset4, filter1, rule6)
	wrapper.addRule(ipset5, filter1, rule6)
	wrapper.addRule(ipset4, filter2, rule7)
	wrapper.addRule(ipset4, filter2, rule6)
	wrapper.addRule(ipset5, filter2, rule6)
	wrapper.addRule(ipset6a, filter3, rule8)
	wrapper.addRule(ipset6b, filter3, rule9)

	// I delete an ipset. Its rules should be deleted.
	if err := wrapper.deleteIpset(ipset2); err != nil {
		t.Errorf("deleteIpset failed: %w", err)
	}
	if wrapper.ruleExists(filter2, rule2) || wrapper.ruleExists(filter1, rule3) || wrapper.ruleExists(filter2, rule3) {
		t.Errorf("deleting ipset 2 did not delete all its rules")
	}
	if !wrapper.ruleExists(filter1, rule1) {
		t.Errorf("deleting ipset 2 deleted extra rules")
	}

	// Delete by prefix
	if err := wrapper.deleteIpsetByPrefix("ipset-6"); err != nil {
		t.Errorf("deleteIpsetByPrefix failed: %w", err)
	}
	if wrapper.ruleExists(filter3, rule8) || wrapper.ruleExists(filter3, rule9) {
		t.Errorf("deleting by prefix did not work")
	}

	// Delete another ipset associated with different filters and other ipsets
	if err := wrapper.deleteIpset(ipset4); err != nil {
		t.Errorf("deleteIpset failed: %w", err)
	}
	if wrapper.ruleExists(filter1, rule5) || wrapper.ruleExists(filter1, rule6) || wrapper.ruleExists(filter2, rule6) || wrapper.ruleExists(filter2, rule7) {
		t.Errorf("deleting ipset 4 did not delete all its rules")
	}

	// Rules 1 and 4 should be remaining
	if !wrapper.ruleExists(filter1, rule1) || !wrapper.ruleExists(filter3, rule1) || !wrapper.ruleExists(filter4, rule1) {
		t.Errorf("expected rule 1 to exist but does not")
	}
	if !wrapper.ruleExists(filter3, rule4) {
		t.Errorf("expected rule 4 to exist but does not")
	}

	// Delete rules 1 and 4 and verify
	wrapper.deleteRule(filter1, rule1)
	wrapper.deleteRule(filter3, rule1)
	wrapper.deleteRule(filter4, rule1)
	wrapper.deleteRule(filter3, rule4)
	if wrapper.ruleExists(filter1, rule1) || wrapper.ruleExists(filter3, rule1) || wrapper.ruleExists(filter4, rule1) || wrapper.ruleExists(filter3, rule4) {
		t.Errorf("deleting rules 1 and 4 did not work")
	}

	// Rules should be gone
	for filterName, ruleCriterias := range wrapper.rules {
		for ruleCriteria := range ruleCriterias {
			t.Errorf("deleted rules but this one for filter %s remains: %s", filterName, ruleCriteria)
		}
	}

	// Now we still have some ipsets not deleted, so their maps may not be empty. Explicitly delete these rules.
	wrapper.deleteRule(filter2, rule2) // in ipset1 map
	wrapper.deleteRule(filter1, rule6) // in ipset5 map
	wrapper.deleteRule(filter2, rule6) // in ipset5 map

	// Verify nothing left in cleaner
	remainingRules := make([]*filterRulePair, 0)
	remainingRules = append(remainingRules,
		append(wrapper.cleaner.getRulesForIpset(ipset1),
			append(wrapper.cleaner.getRulesForIpset(ipset2),
				append(wrapper.cleaner.getRulesForIpset(ipset3),
					append(wrapper.cleaner.getRulesForIpset(ipset4),
						append(wrapper.cleaner.getRulesForIpset(ipset5),
							append(wrapper.cleaner.getRulesForIpset(ipset6a),
								wrapper.cleaner.getRulesForIpset(ipset6b)...)...)...)...)...)...)...)
	for _, frpair := range remainingRules {
		t.Errorf("deleted rules but cleaner still has this one for filter %s: %s", frpair.filterName, frpair.ruleCriteria)
	}
}

// WrapDriver implementation for the test only needs to implement the functions called by the rule cleaner

func (w *wrapperForTest) ListIpsets() ([]string, error) {
	ipsetNames := make([]string, 0, len(w.ipsets))
	for ipsetName := range w.ipsets {
		ipsetNames = append(ipsetNames, ipsetName)
	}
	return ipsetNames, nil
}

func (w *wrapperForTest) DeleteFilterCriteria(filterName, criteriaName string) error {
	delete(w.rules[filterName], criteriaName)
	return nil
}

// Dummy implementations below

func (w *wrapperForTest) GetDestInfo(socket uintptr, destInfo *DestInfo) error {
	return nil
}

func (w *wrapperForTest) ApplyDestHandle(socket, destHandle uintptr) error {
	return nil
}

func (w *wrapperForTest) FreeDestHandle(destHandle uintptr) error {
	return nil
}

func (w *wrapperForTest) NewIpset(name, ipsetType string) (uintptr, error) {
	return 1, nil
}

func (w *wrapperForTest) GetIpset(name string) (uintptr, error) {
	return 1, nil
}

func (w *wrapperForTest) DestroyAllIpsets(prefix string) error {
	return nil
}

func (w *wrapperForTest) ListIpsetsDetail(format int) (string, error) {
	return "", nil
}

func (w *wrapperForTest) IpsetAdd(ipsetHandle uintptr, entry string, timeout int) error {
	return nil
}

func (w *wrapperForTest) IpsetAddOption(ipsetHandle uintptr, entry, option string, timeout int) error {
	return nil
}

func (w *wrapperForTest) IpsetDelete(ipsetHandle uintptr, entry string) error {
	return nil
}

func (w *wrapperForTest) IpsetDestroy(ipsetHandle uintptr, name string) error {
	return nil
}

func (w *wrapperForTest) IpsetFlush(ipsetHandle uintptr) error {
	return nil
}

func (w *wrapperForTest) IpsetTest(ipsetHandle uintptr, entry string) (bool, error) {
	return false, nil
}

func (w *wrapperForTest) PacketFilterStart(firewallName string, receiveCallback, loggingCallback func(uintptr, uintptr) uintptr) error {
	return nil
}

func (w *wrapperForTest) PacketFilterClose() error {
	return nil
}

func (w *wrapperForTest) PacketFilterForward(info *PacketInfo, packetBytes []byte) error {
	return nil
}

func (w *wrapperForTest) AppendFilter(outbound bool, filterName string, isGotoFilter bool) error {
	return nil
}

func (w *wrapperForTest) InsertFilter(outbound bool, priority int, filterName string, isGotoFilter bool) error {
	return nil
}

func (w *wrapperForTest) DestroyFilter(filterName string) error {
	return nil
}

func (w *wrapperForTest) EmptyFilter(filterName string) error {
	return nil
}

func (w *wrapperForTest) GetFilterList(outbound bool) ([]string, error) {
	return nil, nil
}

func (w *wrapperForTest) AppendFilterCriteria(filterName, criteriaName string, ruleSpec *RuleSpec, ipsetRuleSpecs []IpsetRuleSpec) error {
	return nil
}

func (w *wrapperForTest) GetCriteriaList(format int) (string, error) {
	return "", nil
}
