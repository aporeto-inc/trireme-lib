// +build !rhel6

package iptablesctrl

func (i *iptables) aclSkipProto(proto string) bool {
	return false
}

func (i *iptables) legacyPuChainRules(cfg *ACLInfo) ([][]string, bool) {
	return nil, false
}
