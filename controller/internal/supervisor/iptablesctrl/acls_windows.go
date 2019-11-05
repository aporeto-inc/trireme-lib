// +build windows

package iptablesctrl

import (
	"fmt"
	"reflect"
	"strings"

	winipt "go.aporeto.io/trireme-lib/controller/internal/windows"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"

	"go.aporeto.io/trireme-lib/common"
	"go.uber.org/zap"
)

// try to merge two acl rules (one log and one accept/drop) into one for Windows
func makeTerminatingRuleFromPair(aclRule1, aclRule2 []string) *winipt.WindowsRuleSpec {

	if aclRule1 == nil || aclRule2 == nil {
		return nil
	}
	winRuleSpec1, err := winipt.ParseRuleSpec(aclRule1[2:]...)
	if err != nil {
		return nil
	}
	winRuleSpec2, err := winipt.ParseRuleSpec(aclRule2[2:]...)
	if err != nil {
		return nil
	}

	// save action/log properties
	action := winRuleSpec1.Action
	logPrefix := winRuleSpec2.LogPrefix
	groupId := winRuleSpec2.GroupId
	if action == 0 {
		action = winRuleSpec2.Action
		if action == 0 {
			return nil
		}
		logPrefix = winRuleSpec1.LogPrefix
		groupId = winRuleSpec1.GroupId
		if !winRuleSpec1.Log {
			return nil
		}
	} else if !winRuleSpec2.Log {
		return nil
	}

	// if one is nflog and one is another action, and they are otherwise equal, then combine into one rule
	winRuleSpec1.Log = false
	winRuleSpec1.LogPrefix = ""
	winRuleSpec1.GroupId = 0
	winRuleSpec1.Action = 0
	winRuleSpec2.Log = false
	winRuleSpec2.LogPrefix = ""
	winRuleSpec2.GroupId = 0
	winRuleSpec2.Action = 0
	if reflect.DeepEqual(winRuleSpec1, winRuleSpec2) {
		winRuleSpec1.Log = true
		winRuleSpec1.LogPrefix = logPrefix
		winRuleSpec1.GroupId = groupId
		winRuleSpec1.Action = action
		return winRuleSpec1
	}
	return nil
}

// take a parsed acl rule and clean it up, returning an acl rule in []string format
func processWindowsACLRule(table, chain string, winRuleSpec *winipt.WindowsRuleSpec, cfg *ACLInfo, isAppAcls bool) ([]string, error) {
	// update chain name
	if cfg.PUType == common.HostPU {
		if isAppAcls {
			chain = "HostPU-OUTPUT"
		} else {
			chain = "HostPU-INPUT"
		}
	} else if cfg.PUType == common.HostNetworkPU {
		if isAppAcls {
			chain = "HostSvcRules-OUTPUT"
			// TODO(windows): do we need to set source port based on PU?
		} else {
			chain = "HostSvcRules-INPUT"
			// in Windows, our host svc chain is for all host svc PUs, so we need to set destination port
			// to that of the PU to discriminate
			if winRuleSpec.Protocol == packet.IPProtocolTCP {
				winRuleSpec.MatchDstPort, _ = winipt.ParsePortString(cfg.TCPPorts)
			} else if winRuleSpec.Protocol == packet.IPProtocolUDP {
				winRuleSpec.MatchDstPort, _ = winipt.ParsePortString(cfg.UDPPorts)
			}
		}
	} else {
		return nil, fmt.Errorf("unexpected Windows PU: %v", cfg.PUType)
	}
	rulespec := winipt.MakeRuleSpecText(winRuleSpec)
	return append([]string{table, chain}, strings.Split(rulespec, " ")...), nil
}

// while not strictly necessary now for Windows, we still try to combine a log (non-terminating rule) and another terminating rule.
func transformACLRules(aclRules [][]string, cfg *ACLInfo, rulesBucket *rulesInfo, isAppAcls bool) [][]string {

	var result [][]string

	// in the loop, compare successive rules to see if they are equal, disregarding their action or log properties.
	// if they are, then combine them into one rule.
	var aclRule1, aclRule2 []string
	for i := 0; i < len(aclRules) || aclRule1 != nil; i++ {
		if aclRule1 == nil {
			aclRule1 = aclRules[i]
			i++
		}
		if i < len(aclRules) {
			aclRule2 = aclRules[i]
		}
		table, chain := aclRule1[0], aclRule1[1]
		winRule := makeTerminatingRuleFromPair(aclRule1, aclRule2)
		if winRule == nil {
			// not combinable, so work on rule 1
			var err error
			winRule, err = winipt.ParseRuleSpec(aclRule1[2:]...)
			aclRule1 = aclRule2
			aclRule2 = nil
			if err != nil {
				zap.L().Error("transformACLRules failed", zap.Error(err))
				continue
			}
		} else {
			aclRule1 = nil
			aclRule2 = nil
		}
		// process rule
		xformedRule, err := processWindowsACLRule(table, chain, winRule, cfg, isAppAcls)
		if err != nil {
			zap.L().Error("transformACLRules failed", zap.Error(err))
			continue
		}
		result = append(result, xformedRule)
	}

	if result == nil {
		result = [][]string{}
	}
	return result
}
