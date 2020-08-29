// +build windows

package iptablesctrl

import (
	"go.aporeto.io/trireme-lib/controller/internal/windows"
	"go.uber.org/zap"
)

func allowICMPv6(cfg *ACLInfo) {
	// appropriate rules are in rules_windows.go already
}

func icmpRule(icmpTypeCode string, policyRestrictions []string) []string {
	ruleSub, err := windows.ReduceIcmpProtoString(icmpTypeCode, policyRestrictions)
	if err != nil {
		// TODO would be better to be able to return an error so that the whole rule is discarded
		zap.L().Error("could not formulate ICMP rule", zap.Error(err))
	}
	return ruleSub
}
