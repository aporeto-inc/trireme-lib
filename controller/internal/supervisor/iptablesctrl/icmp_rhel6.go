// +build rhel6 darwin

package iptablesctrl

func icmpRule(icmpTypeCode string, policyRestrictions []string) []string {
	return []string{}
}

func allowICMPv6(cfg *ACLInfo) {
}
