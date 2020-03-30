// +build windows

package iptablesctrl

import (
	"fmt"
	"strings"
	"text/template"

	"go.aporeto.io/trireme-lib/v11/controller/constants"
	winipt "go.aporeto.io/trireme-lib/v11/controller/internal/windows"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/v11/monitor/extractors"
	"go.aporeto.io/trireme-lib/v11/policy"

	"go.aporeto.io/trireme-lib/v11/common"
	"go.uber.org/zap"
)

// create ipsets needed for Windows rules
func (i *iptables) platformInit() error {

	cfg, err := i.newACLInfo(0, "", nil, 0)
	if err != nil {
		return err
	}

	existingSets, err := i.ipset.ListIPSets()
	if err != nil {
		return err
	}

	setExists := func(s string) bool {
		for _, existing := range existingSets {
			if existing == s {
				return true
			}
		}
		return false
	}

	if !setExists("TRI-v4-WindowsAllIPs") {
		allIPsV4, err := i.ipset.NewIpset("TRI-v4-WindowsAllIPs", "hash:net", nil)
		if err != nil {
			return err
		}
		err = allIPsV4.Add("0.0.0.0/0", 0)
		if err != nil {
			return err
		}
	}

	if !setExists("TRI-v6-WindowsAllIPs") {
		allIPsV6, err := i.ipset.NewIpset("TRI-v6-WindowsAllIPs", "hash:net", nil)
		if err != nil {
			return err
		}
		err = allIPsV6.Add("::/0", 0)
		if err != nil {
			return err
		}
	}

	if cfg.DNSServerIP != "" && !setExists("TRI-WindowsDNSServer") {
		dnsIPSet, err := i.ipset.NewIpset("TRI-WindowsDNSServer", "hash:net", nil)
		if err != nil {
			return err
		}
		err = dnsIPSet.Add(cfg.DNSServerIP, 0)
		if err != nil {
			return err
		}
	}

	return nil
}

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
	appAnyRules, netAnyRules, err := i.getProtocolAnyRules(cfg, appACLIPset, netACLIPset)
	if err != nil {
		return err
	}
	return i.processRulesFromList(i.trapRules(cfg, isHostPU, appAnyRules, netAnyRules), "Delete")
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

	// save action/log properties, as long as one rule is an action and the other is nflog
	action := 0
	logPrefix := ""
	groupID := 0
	if action == 0 && winRuleSpec1.Action != 0 && winRuleSpec2.Log {
		action = winRuleSpec1.Action
		logPrefix = winRuleSpec2.LogPrefix
		groupID = winRuleSpec2.GroupID
	}
	if action == 0 && winRuleSpec2.Action != 0 && winRuleSpec1.Log {
		action = winRuleSpec2.Action
		logPrefix = winRuleSpec1.LogPrefix
		groupID = winRuleSpec1.GroupID
	}
	if action == 0 {
		return nil
	}

	// if one is nflog and one is another action, and they are otherwise equal, then combine into one rule
	winRuleSpec1.Log = false
	winRuleSpec1.LogPrefix = ""
	winRuleSpec1.GroupID = 0
	winRuleSpec1.Action = 0
	winRuleSpec2.Log = false
	winRuleSpec2.LogPrefix = ""
	winRuleSpec2.GroupID = 0
	winRuleSpec2.Action = 0
	if winRuleSpec1.Equal(winRuleSpec2) {
		winRuleSpec1.Log = true
		winRuleSpec1.LogPrefix = logPrefix
		winRuleSpec1.GroupID = groupID
		winRuleSpec1.Action = action
		return winRuleSpec1
	}
	return nil
}

// take a parsed acl rule and clean it up, returning an acl rule in []string format
func processWindowsACLRule(table, _ string, winRuleSpec *winipt.WindowsRuleSpec, cfg *ACLInfo, isAppAcls bool) ([]string, error) {
	var chain string
	switch cfg.PUType {
	case common.HostPU:
		if isAppAcls {
			chain = "HostPU-OUTPUT"
		} else {
			chain = "HostPU-INPUT"
		}
	case common.HostNetworkPU:
		if isAppAcls {
			return nil, nil
		}
		chain = "HostSvcRules-INPUT"
		// in Windows, our host svc chain is for all host svc PUs, so we need to set destination port
		// to that of the PU in order to discriminate
		switch winRuleSpec.Protocol {
		case packet.IPProtocolTCP:
			winRuleSpec.MatchDstPort, _ = winipt.ParsePortString(cfg.TCPPorts)
		case packet.IPProtocolUDP:
			winRuleSpec.MatchDstPort, _ = winipt.ParsePortString(cfg.UDPPorts)
		default:
			return nil, nil
		}
	default:
		return nil, fmt.Errorf("unexpected Windows PU: %v", cfg.PUType)
	}
	rulespec, _ := winipt.MakeRuleSpecText(winRuleSpec, false)
	return append([]string{table, chain}, strings.Split(rulespec, " ")...), nil
}

// while not strictly necessary now for Windows, we still try to combine a log (non-terminating rule) and another terminating rule.
func transformACLRules(aclRules [][]string, cfg *ACLInfo, rulesBucket *rulesInfo, isAppAcls bool) [][]string {

	// find the reverse rules and remove them.
	// note: we assume that reverse rules are the ones we add for UDP established reverse flows.
	// we handle this in the windows driver so we don't need a rule for it.
	// again: our driver assumes that all UDP acl rules will have a reverse flow added.
	if rulesBucket != nil {
		for _, rr := range rulesBucket.ReverseRules {
			revTable, revChain := rr[0], rr[1]
			revRule, err := winipt.ParseRuleSpec(rr[2:]...)
			if err != nil {
				zap.L().Error("transformACLRules failed to parse reverse rule", zap.Error(err))
				continue
			}
			found := false
			for i, r := range aclRules {
				rule, err := winipt.ParseRuleSpec(r[2:]...)
				if err != nil {
					zap.L().Error("transformACLRules failed to parse rule", zap.Error(err))
					continue
				}
				table, chain := r[0], r[1]
				if table == revTable && chain == revChain && rule.Equal(revRule) {
					found = true
					aclRules = append(aclRules[:i], aclRules[i+1:]...)
					break
				}
			}
			if !found {
				zap.L().Warn("transformACLRules could not find reverse rule")
			}
		}
	}

	var result [][]string

	// now in the loop, compare successive rules to see if they are equal, disregarding their action or log properties.
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
		if xformedRule != nil {
			result = append(result, xformedRule)
		}
	}

	if result == nil {
		result = [][]string{}
	}
	return result
}
