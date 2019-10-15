// +build !windows

package iptablesctrl

func transformACLRules(aclRules [][]string, cfg *ACLInfo, rulesBucket *rulesInfo, isAppAcls bool) [][]string {
	// pass through on linux
	return aclRules
}
