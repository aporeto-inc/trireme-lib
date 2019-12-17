// +build windows

package iptablesctrl

import (
	"fmt"
	"strings"
	"text/template"

	"go.aporeto.io/trireme-lib/controller/constants"
	winipt "go.aporeto.io/trireme-lib/controller/internal/windows"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"

	"go.aporeto.io/trireme-lib/common"
	"go.uber.org/zap"
)

// addContainerChain for Windows
func (i *iptables) addContainerChain(cfg *ACLInfo) error {
	tmpl := template.Must(template.New(globalRules).Funcs(template.FuncMap{
		"isLocalServer": func() bool {
			return i.mode == constants.LocalServer
		},
	}).Parse(``))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}

	for _, rule := range rules {
		zap.L().Error("Creating rules", zap.Strings("rule", rule))
		if err := i.impl.NewChain(rule[1], rule[3]); err != nil {
			return fmt.Errorf("unable to add chain %s of context %s %s", rule[3], rule[1], err)
		}
	}

	return nil
}

// deletePUChains removes all the container specific chains and basic rules
func (i *iptables) deletePUChains(cfg *ACLInfo, containerInfo *policy.PUInfo) error {

	// For Windows, instead of clearing and deleting the app-chain and the net-chain, we need to
	// delete individual rules. This is because Windows uses non-PU-specific chains.

	// delete ACLs rules for Windows
	appACLIPset := i.getACLIPSets(containerInfo.Policy.ApplicationACLs())
	netACLIPset := i.getACLIPSets(containerInfo.Policy.NetworkACLs())

	if err := i.deleteExternalACLs(cfg, cfg.AppChain, cfg.NetChain, appACLIPset, true); err != nil {
		zap.L().Warn("Failed to delete ACL rules for app chain", zap.Error(err))
	}

	if err := i.deleteExternalACLs(cfg, cfg.NetChain, cfg.AppChain, netACLIPset, false); err != nil {
		zap.L().Warn("Failed to delete ACL rules for net chain", zap.Error(err))
	}

	// delete deny-all rules for Windows
	isHostPU := extractors.IsHostPU(containerInfo.Runtime, i.mode)
	return i.processRulesFromList(i.trapRules(cfg, isHostPU, [][]string{}, [][]string{}), "Delete")
}

// delete windows acl rules explicitly, because we can't just clear chains.
// note: the same transforms etc that apply in addExternalACLs must also apply here.
func (i *iptables) deleteExternalACLs(cfg *ACLInfo, chain string, reverseChain string, rules []aclIPset, isAppAcls bool) error {

	_, rules = extractProtocolAnyRules(rules)

	rulesBucket := i.sortACLsInBuckets(cfg, chain, reverseChain, rules, isAppAcls)

	aclRules, err := extractACLsFromTemplate(rulesBucket)
	if err != nil {
		return fmt.Errorf("unable to extract rules from template: %s", err)
	}

	aclRules = transformACLRules(aclRules, cfg, rulesBucket, isAppAcls)

	if err := i.processRulesFromList(aclRules, "Delete"); err != nil {
		return fmt.Errorf("unable to delete rules - mode :%s %v", err, isAppAcls)
	}

	return nil
}

// removeGlobalHooksPre for Windows does nothing
func (i *iptables) removeGlobalHooksPre() {
}

type ruleTransformData struct {
	isAppAcls bool
	aclRule   []string
}

// try to merge two acl rules (one log and one accept/drop) into one for Windows
func makeTerminatingRuleFromPair(ruleData1, ruleData2 *ruleTransformData) *winipt.WindowsRuleSpec {

	if ruleData1 == nil || ruleData2 == nil {
		return nil
	}
	if ruleData1.isAppAcls != ruleData2.isAppAcls {
		// must be in same direction in order to combine
		return nil
	}

	aclRule1, aclRule2 := ruleData1.aclRule, ruleData2.aclRule
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

	// save action/log properties, as long as one rule is an action and the other is nflog
	action := 0
	logPrefix := ""
	groupId := 0
	if action == 0 && winRuleSpec1.Action != 0 && winRuleSpec2.Log {
		action = winRuleSpec1.Action
		logPrefix = winRuleSpec2.LogPrefix
		groupId = winRuleSpec2.GroupId
	}
	if action == 0 && winRuleSpec2.Action != 0 && winRuleSpec1.Log {
		action = winRuleSpec2.Action
		logPrefix = winRuleSpec1.LogPrefix
		groupId = winRuleSpec1.GroupId
	}
	if action == 0 {
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
	if winRuleSpec1.Equal(winRuleSpec2) {
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
	switch cfg.PUType {
	case common.HostPU:
		if isAppAcls {
			chain = "HostPU-OUTPUT"
		} else {
			chain = "HostPU-INPUT"
		}
	case common.HostNetworkPU:
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
	default:
		return nil, fmt.Errorf("unexpected Windows PU: %v", cfg.PUType)
	}
	rulespec, _ := winipt.MakeRuleSpecText(winRuleSpec, false)
	return append([]string{table, chain}, strings.Split(rulespec, " ")...), nil
}

// while not strictly necessary now for Windows, we still try to combine a log (non-terminating rule) and another terminating rule.
func transformACLRules(aclRules [][]string, cfg *ACLInfo, rulesBucket *rulesInfo, isAppAcls bool) [][]string {

	// handle reverse rules by first building a structure that maintains an app/net direction per rule
	rulesToProcess := make([]*ruleTransformData, len(aclRules))
	for i, r := range aclRules {
		rulesToProcess[i] = &ruleTransformData{isAppAcls: isAppAcls, aclRule: r}
	}

	// find the reverse rules and reverse their direction
	for _, rr := range rulesBucket.ReverseRules {
		revTable, revChain := rr[0], rr[1]
		revRule, err := winipt.ParseRuleSpec(rr[2:]...)
		if err != nil {
			zap.L().Error("transformACLRules failed to parse reverse rule", zap.Error(err))
			continue
		}
		found := false
		for _, r := range rulesToProcess {
			if r.isAppAcls != isAppAcls {
				// skip already-reversed rules
				continue
			}
			rule, err := winipt.ParseRuleSpec(r.aclRule[2:]...)
			if err != nil {
				zap.L().Error("transformACLRules failed to parse rule", zap.Error(err))
				continue
			}
			table, chain := r.aclRule[0], r.aclRule[1]
			if table == revTable && chain == revChain && rule.Equal(revRule) {
				r.isAppAcls = !isAppAcls
				found = true
				break
			}
		}
		if !found {
			zap.L().Warn("transformACLRules could not find reverse rule")
		}
	}

	var result [][]string

	// now in the loop, compare successive rules to see if they are equal, disregarding their action or log properties.
	// if they are, then combine them into one rule.
	var ruleData1, ruleData2 *ruleTransformData
	for i := 0; i < len(rulesToProcess) || ruleData1 != nil; i++ {
		if ruleData1 == nil {
			ruleData1 = rulesToProcess[i]
			i++
		}
		if i < len(rulesToProcess) {
			ruleData2 = rulesToProcess[i]
		}
		table, chain, isAppAclsLocal := ruleData1.aclRule[0], ruleData1.aclRule[1], ruleData1.isAppAcls
		winRule := makeTerminatingRuleFromPair(ruleData1, ruleData2)
		if winRule == nil {
			// not combinable, so work on rule 1
			var err error
			winRule, err = winipt.ParseRuleSpec(ruleData1.aclRule[2:]...)
			ruleData1 = ruleData2
			ruleData2 = nil
			if err != nil {
				zap.L().Error("transformACLRules failed", zap.Error(err))
				continue
			}
		} else {
			ruleData1 = nil
			ruleData2 = nil
		}
		// process rule
		xformedRule, err := processWindowsACLRule(table, chain, winRule, cfg, isAppAclsLocal)
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
