package iptablesctrl

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/template"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

const (
	tcpProto     = "tcp"
	udpProto     = "udp"
	numPackets   = "100"
	initialCount = "99"
)

type rulesInfo struct {
	RejectObserveApply    [][]string
	RejectNotObserved     [][]string
	RejectObserveContinue [][]string

	AcceptObserveApply    [][]string
	AcceptNotObserved     [][]string
	AcceptObserveContinue [][]string

	ReverseRules [][]string
}

// cgroupChainRules provides the rules for redirecting to a processing unit
// specific chain based for Linux processed and based on the cgroups and net_cls
// configuration.
func (i *Instance) cgroupChainRules(cfg *ACLInfo) [][]string {

	// Rules for older distros (eg RH 6.9/Ubuntu 14.04), due to absence of
	// cgroup match modules, source ports are used  to trap outgoing traffic.
	if i.isLegacyKernel && (cfg.PUType == common.HostNetworkPU || cfg.PUType == common.HostPU) {
		return i.legacyPuChainRules(
			cfg.ContextID,
			cfg.AppChain,
			cfg.NetChain,
			cfg.CgroupMark,
			cfg.TCPPorts,
			cfg.UDPPorts,
			cfg.ProxyPort,
			cfg.ProxySetName,
			cfg.AppSection,
			cfg.NetSection,
			cfg.PUType,
		)
	}

	tmpl := template.Must(template.New(cgroupCaptureTemplate).Funcs(template.FuncMap{
		"isUDPPorts": func() bool {
			return cfg.UDPPorts != "0"
		},
		"isTCPPorts": func() bool {
			return cfg.TCPPorts != "0"
		},
		"isHostPU": func() bool {
			return cfg.AppSection == HostModeOutput && cfg.NetSection == HostModeInput
		},
	}).Parse(cgroupCaptureTemplate))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}

	return append(rules, i.proxyRules(cfg)...)
}

func (i *Instance) uidChainRules(cfg *ACLInfo) [][]string {

	tmpl := template.Must(template.New(uidChainTemplate).Parse(uidChainTemplate))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}

	if i.isLegacyKernel {
		return append(rules, i.legacyProxyRules(cfg.TCPPorts, cfg.ProxyPort, cfg.ProxySetName, cfg.CgroupMark)...)
	}
	return append(rules, i.proxyRules(cfg)...)
}

// containerChainRules provides the list of rules that are used to send traffic to
// a particular chain
func (i *Instance) containerChainRules(cfg *ACLInfo) [][]string {

	tmpl := template.Must(template.New(containerChainTemplate).Parse(containerChainTemplate))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}

	return append(rules, i.proxyRules(cfg)...)
}

// proxyRules creates the rules that allow traffic to go through if it is handled
// by the services.
func (i *Instance) proxyRules(cfg *ACLInfo) [][]string {

	tmpl := template.Must(template.New(proxyChainTemplate).Funcs(template.FuncMap{
		"isCgroupSet": func() bool {
			return cfg.CgroupMark != ""
		},
	}).Parse(proxyChainTemplate))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}
	return rules
}

// trapRules provides the packet capture rules that are defined for each processing unit.
func (i *Instance) trapRules(cfg *ACLInfo, isHostPU bool) [][]string {

	tmpl := template.Must(template.New(packetCaptureTemplate).Funcs(template.FuncMap{
		"needDnsRules": func() bool {
			return i.mode == constants.Sidecar || isHostPU || i.isLegacyKernel
		},
		"isUIDProcess": func() bool {
			return cfg.UID != ""
		},
	}).Parse(packetCaptureTemplate))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}

	return rules
}

// addContainerChain adds a chain for the specific container and redirects traffic there
// This simplifies significantly the management and makes the iptable rules more readable
// All rules related to a container are contained within the dedicated chain
func (i *Instance) addContainerChain(appChain string, netChain string) error {

	if err := i.ipt.NewChain(i.appPacketIPTableContext, appChain); err != nil {
		return fmt.Errorf("unable to add chain %s of context %s: %s", appChain, i.appPacketIPTableContext, err)
	}

	if err := i.ipt.NewChain(i.netPacketIPTableContext, netChain); err != nil {
		return fmt.Errorf("unable to add netchain %s of context %s: %s", netChain, i.netPacketIPTableContext, err)
	}

	return nil
}

// processRulesFromList is a generic helper that parses a set of rules and sends the corresponding
// ACL commands.
func (i *Instance) processRulesFromList(rulelist [][]string, methodType string) error {
	var err error
	for _, cr := range rulelist {
		// HACK: Adding a retry loop to avoid iptables error of "invalid argument"
		// Once in a while iptables
	L:
		for retry := 0; retry < 3; retry++ {
			switch methodType {
			case "Append":
				if err = i.ipt.Append(cr[0], cr[1], cr[2:]...); err == nil {
					break L
				}
			case "Insert":
				order, err := strconv.Atoi(cr[2])
				if err != nil {
					zap.L().Error("Incorrect format for iptables insert")
					return errors.New("invalid format")
				}
				if err = i.ipt.Insert(cr[0], cr[1], order, cr[3:]...); err == nil {
					break L
				}

			case "Delete":
				if err = i.ipt.Delete(cr[0], cr[1], cr[2:]...); err == nil {
					break L
				}

			default:
				return errors.New("invalid method type")
			}
		}
		if err != nil && methodType != "Delete" {
			return fmt.Errorf("unable to %s rule for table %s and chain %s with error %s", methodType, cr[0], cr[1], err)
		}
	}

	return nil
}

// addChainrules implements all the iptable rules that redirect traffic to a chain
func (i *Instance) addChainRules(cfg *ACLInfo) error {

	if i.mode != constants.LocalServer {
		return i.processRulesFromList(i.containerChainRules(cfg), "Append")
	}

	if cfg.UID != "" {
		return i.processRulesFromList(i.uidChainRules(cfg), "Append")
	}

	return i.processRulesFromList(i.cgroupChainRules(cfg), "Append")
}

// addPacketTrap adds the necessary iptables rules to capture control packets to user space
func (i *Instance) addPacketTrap(cfg *ACLInfo, isHostPU bool) error {

	return i.processRulesFromList(i.trapRules(cfg, isHostPU), "Append")
}

func (i *Instance) generateACLRules(contextID string, rule *aclIPset, chain string, reverseChain string, nfLogGroup, proto, ipMatchDirection string, reverseDirection string) ([][]string, [][]string) {
	iptRules := [][]string{}
	reverseRules := [][]string{}
	observeContinue := rule.policy.ObserveAction.ObserveContinue()

	baseRule := func(proto string) []string {
		iptRule := []string{
			i.appPacketIPTableContext,
			chain,
			"-p", proto,
			"-m", "set", "--match-set", rule.ipset, ipMatchDirection,
		}

		if proto == constants.TCPProtoNum || proto == constants.TCPProtoString {
			stateMatch := []string{"-m", "state", "--state", "NEW"}
			iptRule = append(iptRule, stateMatch...)
		}

		// only tcp uses target networks
		if proto == constants.TCPProtoNum || proto == constants.TCPProtoString {
			targetNet := []string{"-m", "set", "!", "--match-set", targetTCPNetworkSet, ipMatchDirection}
			iptRule = append(iptRule, targetNet...)
		}

		// port match is required only for tcp and udp protocols
		if proto == constants.TCPProtoNum || proto == constants.UDPProtoNum || proto == constants.TCPProtoString || proto == constants.UDPProtoString {
			portMatchSet := []string{"--match", "multiport", "--dports", strings.Join(rule.ports, ",")}
			iptRule = append(iptRule, portMatchSet...)
		}

		return iptRule
	}

	if rule.policy.Action&policy.Log > 0 || observeContinue {
		nflog := []string{"-m", "state", "--state", "NEW",
			"-j", "NFLOG", "--nflog-group", nfLogGroup, "--nflog-prefix", rule.policy.LogPrefix(contextID)}
		nfLogRule := append(baseRule(proto), nflog...)

		iptRules = append(iptRules, nfLogRule)
	}

	if !observeContinue {
		if (rule.policy.Action & policy.Accept) != 0 {
			accept := []string{"-j", "ACCEPT"}
			acceptRule := append(baseRule(proto), accept...)
			iptRules = append(iptRules, acceptRule)
		}

		if rule.policy.Action&policy.Reject != 0 {
			reject := []string{"-j", "DROP"}
			rejectRule := append(baseRule(proto), reject...)
			iptRules = append(iptRules, rejectRule)
		}

		if rule.policy.Action&policy.Accept != 0 && (proto == constants.UDPProtoNum || proto == constants.UDPProtoString) {
			reverseRules = append(reverseRules, []string{
				i.appPacketIPTableContext,
				reverseChain,
				"-p", proto,
				"-m", "set", "--match-set", rule.ipset, reverseDirection,
				"-m", "state", "--state", "ESTABLISHED",
				"-j", "ACCEPT",
			})
		}
	}

	return iptRules, reverseRules
}

// sortACLsInBuckets will process all the rules and add them in a list of buckets
// based on their priority. We need an explicit order of these buckets
// in order to support observation only of ACL actions. The parameters
// must provide the chain and whether it is App or Net ACLs so that the rules
// can be created accordingly.
func (i *Instance) sortACLsInBuckets(contextID, chain string, reverseChain string, rules []aclIPset, isAppACLs bool) *rulesInfo {

	rulesBucket := &rulesInfo{
		RejectObserveApply:    [][]string{},
		RejectNotObserved:     [][]string{},
		RejectObserveContinue: [][]string{},
		AcceptObserveApply:    [][]string{},
		AcceptNotObserved:     [][]string{},
		AcceptObserveContinue: [][]string{},
		ReverseRules:          [][]string{},
	}

	direction := "src"
	reverse := "dst"
	nflogGroup := "11"
	if isAppACLs {
		direction = "dst"
		reverse = "src"
		nflogGroup = "10"
	}

	for _, rule := range rules {

		for _, proto := range rule.protocols {

			acls, r := i.generateACLRules(contextID, &rule, chain, reverseChain, nflogGroup, proto, direction, reverse)
			rulesBucket.ReverseRules = append(rulesBucket.ReverseRules, r...)

			if testReject(rule.policy) && testObserveApply(rule.policy) {
				rulesBucket.RejectObserveApply = append(rulesBucket.RejectObserveApply, acls...)
			}

			if testReject(rule.policy) && testNotObserved(rule.policy) {
				rulesBucket.RejectNotObserved = append(rulesBucket.RejectNotObserved, acls...)
			}

			if testReject(rule.policy) && testObserveContinue(rule.policy) {
				rulesBucket.RejectObserveContinue = append(rulesBucket.RejectObserveContinue, acls...)
			}

			if testAccept(rule.policy) && testObserveContinue(rule.policy) {
				rulesBucket.AcceptObserveContinue = append(rulesBucket.AcceptObserveContinue, acls...)
			}

			if testAccept(rule.policy) && testNotObserved(rule.policy) {
				rulesBucket.AcceptNotObserved = append(rulesBucket.AcceptNotObserved, acls...)
			}

			if testAccept(rule.policy) && testObserveApply(rule.policy) {
				rulesBucket.AcceptObserveApply = append(rulesBucket.AcceptObserveApply, acls...)
			}
		}
	}

	return rulesBucket
}

// addExternalACLs adds a set of rules to the external services that are initiated
// by an application. The allow rules are inserted with highest priority.
func (i *Instance) addExternalACLs(contextID string, chain string, reverseChain string, rules []aclIPset, isAppAcls bool) error {

	rulesBucket := i.sortACLsInBuckets(contextID, chain, reverseChain, rules, isAppAcls)

	tmpl := template.Must(template.New(acls).Funcs(template.FuncMap{
		"joinRule": func(rule []string) string {
			return strings.Join(rule, " ")
		},
	}).Parse(acls))

	aclRules, err := extractRulesFromTemplate(tmpl, *rulesBucket)
	if err != nil {
		return fmt.Errorf("unable to extract rules from template: %s", err)
	}

	if err := i.processRulesFromList(aclRules, "Append"); err != nil {
		return fmt.Errorf("unable to install rules - mode :%s %v", err, isAppAcls)
	}

	return nil
}

// deleteChainRules deletes the rules that send traffic to our chain
func (i *Instance) deleteChainRules(cfg *ACLInfo) error {

	if i.mode != constants.LocalServer {
		return i.processRulesFromList(i.containerChainRules(cfg), "Delete")
	}

	if cfg.UID != "" {
		return i.processRulesFromList(i.uidChainRules(cfg), "Delete")
	}

	return i.processRulesFromList(i.cgroupChainRules(cfg), "Delete")
}

// deletePUChains removes all the container specific chains and basic rules
func (i *Instance) deletePUChains(appChain, netChain string) error {

	if err := i.ipt.ClearChain(i.appPacketIPTableContext, appChain); err != nil {
		zap.L().Warn("Failed to clear the container ack packets chain",
			zap.String("appChain", appChain),
			zap.String("context", i.appPacketIPTableContext),
			zap.Error(err),
		)
	}

	if err := i.ipt.DeleteChain(i.appPacketIPTableContext, appChain); err != nil {
		zap.L().Warn("Failed to delete the container ack packets chain",
			zap.String("appChain", appChain),
			zap.String("context", i.appPacketIPTableContext),
			zap.Error(err),
		)
	}

	if err := i.ipt.ClearChain(i.netPacketIPTableContext, netChain); err != nil {
		zap.L().Warn("Failed to clear the container net packets chain",
			zap.String("netChain", netChain),
			zap.String("context", i.netPacketIPTableContext),
			zap.Error(err),
		)
	}

	if err := i.ipt.DeleteChain(i.netPacketIPTableContext, netChain); err != nil {
		zap.L().Warn("Failed to delete the container net packets chain",
			zap.String("netChain", netChain),
			zap.String("context", i.netPacketIPTableContext),
			zap.Error(err),
		)
	}

	return nil
}

// setGlobalRules installs the global rules
func (i *Instance) setGlobalRules() error {

	cfg, err := i.newACLInfo(0, "", nil, 0)
	if err != nil {
		return err
	}

	tmpl := template.Must(template.New(globalRules).Funcs(template.FuncMap{
		"isLocalServer": func() bool {
			return i.mode == constants.LocalServer
		},
	}).Parse(globalRules))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}

	if err := i.processRulesFromList(rules, "Append"); err != nil {
		return fmt.Errorf("unable to install global rules:%s", err)
	}

	// nat rules cannot be templated, since they interfere with Docker.
	err = i.ipt.Insert(i.appProxyIPTableContext,
		ipTableSectionPreRouting, 1,
		"-p", "tcp",
		"-m", "addrtype", "--dst-type", "LOCAL",
		"-m", "set", "!", "--match-set", excludedNetworkSet, "src",
		"-j", natProxyInputChain)
	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at net: %s", err)
	}

	err = i.ipt.Insert(i.appProxyIPTableContext,
		ipTableSectionOutput, 1,
		"-m", "set", "!", "--match-set", excludedNetworkSet, "dst",
		"-j", natProxyOutputChain)
	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at net: %s", err)
	}

	return nil
}

func (i *Instance) removeGlobalHooks(cfg *ACLInfo) error {

	tmpl := template.Must(template.New(globalHooks).Funcs(template.FuncMap{
		"isLocalServer": func() bool {
			return i.mode == constants.LocalServer
		},
	}).Parse(globalHooks))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		return fmt.Errorf("unable to create trireme chains:%s", err)
	}

	i.processRulesFromList(rules, "Delete") // nolint
	return nil
}

func (i *Instance) cleanACLs() error { // nolint
	cfg, err := i.newACLInfo(0, "", nil, 0)
	if err != nil {
		return err
	}

	// First clear the nat rules
	if err := i.removeGlobalHooks(cfg); err != nil {
		zap.L().Error("unable to remove nat proxy rules")
	}

	tmpl := template.Must(template.New(deleteChains).Funcs(template.FuncMap{
		"isLocalServer": func() bool {
			return i.mode == constants.LocalServer
		},
	}).Parse(deleteChains))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		return fmt.Errorf("unable to create trireme chains:%s", err)
	}

	for _, rule := range rules {
		if len(rule) != 4 {
			continue
		}

		// Flush the chains
		if rule[2] == "-F" {
			if err := i.ipt.ClearChain(rule[1], rule[3]); err != nil {
				zap.L().Error("unable to flush chain", zap.String("table", rule[1]), zap.String("chain", rule[3]), zap.Error(err))
			}
		}

		// Delete the chains
		if rule[2] == "-X" {
			if err := i.ipt.DeleteChain(rule[1], rule[3]); err != nil {
				zap.L().Error("unable to delete chain", zap.String("table", rule[1]), zap.String("chain", rule[3]), zap.Error(err))
			}
		}
	}

	// Clean Application Rules/Chains
	i.cleanACLSection(i.appPacketIPTableContext, chainPrefix)

	i.ipt.Commit() // nolint

	// Always return nil here. No reason to block anything if cleans fail.
	return nil
}

// cleanACLSection flushes and deletes all chains with Prefix - Trireme
func (i *Instance) cleanACLSection(context, chainPrefix string) {

	rules, err := i.ipt.ListChains(context)
	if err != nil {
		zap.L().Warn("Failed to list chains",
			zap.String("context", context),
			zap.Error(err),
		)
	}

	for _, rule := range rules {

		if strings.Contains(rule, chainPrefix) {
			if err := i.ipt.ClearChain(context, rule); err != nil {
				zap.L().Warn("Can not clear the chain",
					zap.String("context", context),
					zap.String("section", rule),
					zap.Error(err),
				)
			}
			if err := i.ipt.DeleteChain(context, rule); err != nil {
				zap.L().Warn("Can not delete the chain",
					zap.String("context", context),
					zap.String("section", rule),
					zap.Error(err),
				)
			}
		}
	}
}
