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
		zap.L().Debug("could not formulate ICMP rule", zap.Error(err))
		// we cannot return empty because it will match all icmp
		ruleSub = windows.GetIcmpNoMatch()
	}
	return ruleSub
}
