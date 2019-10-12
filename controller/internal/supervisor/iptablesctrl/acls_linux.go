// +build linux

package iptablesctrl

func transformACLRules(aclRules [][]string, cfg *ACLInfo, rulesBucket *rulesInfo, isAppAcls bool) ([][]string, error) {
	// pass through on linux
	return aclRules, nil
}
