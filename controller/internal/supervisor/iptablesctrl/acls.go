package iptablesctrl

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/template"

	"github.com/mattn/go-shellwords"
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
func (i *iptables) cgroupChainRules(cfg *ACLInfo) [][]string {

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
			cfg.DNSProxyPort,
			cfg.DNSServerIP,
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

func (i *iptables) uidChainRules(cfg *ACLInfo) [][]string {

	tmpl := template.Must(template.New(uidChainTemplate).Parse(uidChainTemplate))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}

	if i.isLegacyKernel {
		return append(rules, i.legacyProxyRules(cfg.TCPPorts, cfg.ProxyPort, cfg.ProxySetName, cfg.CgroupMark, cfg.DNSProxyPort, cfg.DNSServerIP)...)
	}
	return append(rules, i.proxyRules(cfg)...)
}

// containerChainRules provides the list of rules that are used to send traffic to
// a particular chain
func (i *iptables) containerChainRules(cfg *ACLInfo) [][]string {

	tmpl := template.Must(template.New(containerChainTemplate).Parse(containerChainTemplate))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}

	return append(rules, i.proxyRules(cfg)...)
}

// proxyRules creates the rules that allow traffic to go through if it is handled
// by the services.
func (i *iptables) proxyRules(cfg *ACLInfo) [][]string {

	tmpl := template.Must(template.New(proxyChainTemplate).Funcs(template.FuncMap{
		"isCgroupSet": func() bool {
			return cfg.CgroupMark != ""
		},
		"enableDNSProxy": func() bool {
			return cfg.DNSServerIP != ""
		},
	}).Parse(proxyChainTemplate))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}
	return rules
}

// trapRules provides the packet capture rules that are defined for each processing unit.
func (i *iptables) trapRules(cfg *ACLInfo, isHostPU bool) [][]string {

	tmpl := template.Must(template.New(packetCaptureTemplate).Funcs(template.FuncMap{
		"needDnsRules": func() bool {
			return i.mode == constants.Sidecar || isHostPU || i.isLegacyKernel
		},
		"isUIDProcess": func() bool {
			return cfg.UID != ""
		},
		"needICMP": func() bool {
			return cfg.needICMPRules
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
func (i *iptables) addContainerChain(appChain string, netChain string) error {

	if err := i.impl.NewChain(appPacketIPTableContext, appChain); err != nil {
		return fmt.Errorf("unable to add chain %s of context %s: %s", appChain, appPacketIPTableContext, err)
	}

	// if err := i.impl.NewChain(appProxyIPTableContext, appChain); err != nil {
	// 	return fmt.Errorf("unable to add chain %s of context %s: %s", appChain, appPacketIPTableContext, err)
	// }

	if err := i.impl.NewChain(netPacketIPTableContext, netChain); err != nil {
		return fmt.Errorf("unable to add netchain %s of context %s: %s", netChain, netPacketIPTableContext, err)
	}

	return nil
}

// processRulesFromList is a generic helper that parses a set of rules and sends the corresponding
// ACL commands.
func (i *iptables) processRulesFromList(rulelist [][]string, methodType string) error {
	var err error
	for _, cr := range rulelist {
		// HACK: Adding a retry loop to avoid iptables error of "invalid argument"
		// Once in a while iptables
	L:
		for retry := 0; retry < 3; retry++ {
			switch methodType {
			case "Append":
				if err = i.impl.Append(cr[0], cr[1], cr[2:]...); err == nil {
					break L
				}
			case "Insert":
				order, err := strconv.Atoi(cr[2])
				if err != nil {
					zap.L().Error("Incorrect format for iptables insert")
					return errors.New("invalid format")
				}
				if err = i.impl.Insert(cr[0], cr[1], order, cr[3:]...); err == nil {
					break L
				}

			case "Delete":
				if err = i.impl.Delete(cr[0], cr[1], cr[2:]...); err == nil {
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
func (i *iptables) addChainRules(cfg *ACLInfo) error {

	if i.mode != constants.LocalServer {
		return i.processRulesFromList(i.containerChainRules(cfg), "Append")
	}

	if cfg.UID != "" {
		return i.processRulesFromList(i.uidChainRules(cfg), "Append")
	}

	return i.processRulesFromList(i.cgroupChainRules(cfg), "Append")
}

// addPacketTrap adds the necessary iptables rules to capture control packets to user space
func (i *iptables) addPacketTrap(cfg *ACLInfo, isHostPU bool) error {

	// We insert the udp nfq rule at the top of the pu chain, before the external acls.
	udpNfqRule := []string{
		"-p", "udp",
		"-m", "set", "--match-set", cfg.TargetUDPNetSet, "dst",
		"-j", "NFQUEUE", "--queue-balance", cfg.QueueBalanceAppSyn,
	}

	if err := i.impl.Insert(appPacketIPTableContext, cfg.AppChain, 1, udpNfqRule...); err != nil {
		return err
	}

	return i.processRulesFromList(i.trapRules(cfg, isHostPU), "Append")
}

func (i *iptables) generateACLRules(cfg *ACLInfo, rule *aclIPset, chain string, reverseChain string, nfLogGroup, proto, ipMatchDirection string, reverseDirection string) ([][]string, [][]string) {
	iptRules := [][]string{}
	reverseRules := [][]string{}

	ipsetPrefix := i.impl.GetIPSetPrefix()
	observeContinue := rule.policy.ObserveAction.ObserveContinue()
	contextID := cfg.ContextID

	baseRule := func(proto string) []string {
		iptRule := []string{
			appPacketIPTableContext,
			chain,
			"-p", proto,
			"-m", "set", "--match-set", rule.ipset, ipMatchDirection,
		}

		if proto == constants.AllProtoString {
			iptRule = []string{
				appPacketIPTableContext,
				chain,
				"!", "-p", "tcp",
				"-m", "set", "--match-set", rule.ipset, ipMatchDirection,
			}
		}

		if proto == constants.TCPProtoNum || proto == constants.TCPProtoString {
			stateMatch := []string{"-m", "state", "--state", "NEW"}
			iptRule = append(iptRule, stateMatch...)
		}

		// only tcp uses target networks
		if proto == constants.TCPProtoNum || proto == constants.TCPProtoString {
			targetNet := []string{"-m", "set", "!", "--match-set", ipsetPrefix + targetTCPNetworkSet, ipMatchDirection}
			iptRule = append(iptRule, targetNet...)
		}

		// port match is required only for tcp and udp protocols
		if proto == constants.TCPProtoNum || proto == constants.UDPProtoNum || proto == constants.TCPProtoString || proto == constants.UDPProtoString {
			portMatchSet := []string{"--match", "multiport", "--dports", strings.Join(rule.ports, ",")}
			iptRule = append(iptRule, portMatchSet...)
		}

		return iptRule
	}

	if err := i.programExtensionsRules(contextID, rule, chain, proto, ipMatchDirection, nfLogGroup); err != nil {
		zap.L().Warn("unable to program extension rules",
			zap.Error(err),
		)
	}

	if rule.policy.Action&policy.Log > 0 || observeContinue {
		nflog := []string{"-m", "state", "--state", "NEW",
			"-j", "NFLOG", "--nflog-group", nfLogGroup, "--nflog-prefix", rule.policy.LogPrefix(contextID)}
		nfLogRule := append(baseRule(proto), nflog...)

		iptRules = append(iptRules, nfLogRule)
	}

	if !observeContinue {
		if (rule.policy.Action & policy.Accept) != 0 {
			acceptRule := append(baseRule(proto), []string{"-j", "ACCEPT"}...)
			iptRules = append(iptRules, acceptRule)
		}

		if rule.policy.Action&policy.Reject != 0 {
			reject := []string{"-j", "DROP"}
			rejectRule := append(baseRule(proto), reject...)
			iptRules = append(iptRules, rejectRule)
		}

		if rule.policy.Action&policy.Accept != 0 {
			ipRule := []string{}

			// If it is 'all', we add established accept rule with  !tcp.
			if proto == constants.AllProtoString {
				ipRule = []string{
					appPacketIPTableContext,
					reverseChain,
					"!", "-p", "tcp",
					"-m", "set", "--match-set", rule.ipset, reverseDirection,
					"-m", "state", "--state", "ESTABLISHED",
					"-j", "ACCEPT",
				}
				// If its not TCP, we add established accept rule with given protocol.
			} else if proto != constants.TCPProtoNum && proto != constants.TCPProtoString {
				ipRule = []string{
					appPacketIPTableContext,
					reverseChain,
					"-p", proto,
					"-m", "set", "--match-set", rule.ipset, reverseDirection,
					"-m", "state", "--state", "ESTABLISHED",
					"-j", "ACCEPT",
				}
			}

			reverseRules = append(reverseRules, ipRule)
		}
	}

	return iptRules, reverseRules
}

// programExtensionsRules programs iptable rules for the given extensions
func (i *iptables) programExtensionsRules(contextID string, rule *aclIPset, chain, proto, ipMatchDirection, nfLogGroup string) error {

	rulesspec := []string{
		"-p", proto,
		"-m", "set", "--match-set", rule.ipset, ipMatchDirection,
	}

	for _, ext := range rule.extensions {
		if rule.policy.Action&policy.Log > 0 {
			if err := i.programNflogExtensionRule(contextID, rule, rulesspec, ext, chain, nfLogGroup); err != nil {
				return fmt.Errorf("unable to program nflog extension: %v", err)
			}
		}

		args, err := shellwords.Parse(ext)
		if err != nil {
			return fmt.Errorf("unable to parse extension %s: %v", ext, err)
		}

		extRulesSpec := append(rulesspec, args...)
		if err := i.impl.Append(appPacketIPTableContext, chain, extRulesSpec...); err != nil {
			return fmt.Errorf("unable to program extension rules: %v", err)
		}
	}

	return nil
}

// WARNING: The extension should always contain the action at the end else,
// the function returns error.
func (i *iptables) programNflogExtensionRule(contextID string, rule *aclIPset, rulesspec []string, ext string, chain, nfLogGroup string) error {

	parts := strings.SplitN(ext, " -j ", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid extension format: %s", ext)
	}
	filter, target := parts[0], parts[1]

	if filter == "" || target == "" {
		return fmt.Errorf("filter or target is empty: %s", ext)
	}

	filterArgs, err := shellwords.Parse(filter)
	if err != nil {
		return fmt.Errorf("unable to parse extension %s: %v", ext, err)
	}

	action := "3"
	if target == "DROP" {
		action = "6"
	}

	defaultNflogSuffix := []string{"-m", "state", "--state", "NEW",
		"-j", "NFLOG", "--nflog-group", nfLogGroup, "--nflog-prefix", rule.policy.LogPrefixAction(contextID, action)}
	filterArgs = append(filterArgs, defaultNflogSuffix...)

	nflogRulesspec := append(rulesspec, filterArgs...)
	return i.impl.Append(appPacketIPTableContext, chain, nflogRulesspec...)
}

// sortACLsInBuckets will process all the rules and add them in a list of buckets
// based on their priority. We need an explicit order of these buckets
// in order to support observation only of ACL actions. The parameters
// must provide the chain and whether it is App or Net ACLs so that the rules
// can be created accordingly.
func (i *iptables) sortACLsInBuckets(cfg *ACLInfo, chain string, reverseChain string, rules []aclIPset, isAppACLs bool) *rulesInfo {

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

			if !i.impl.ProtocolAllowed(proto) {
				continue
			}

			acls, r := i.generateACLRules(cfg, &rule, chain, reverseChain, nflogGroup, proto, direction, reverse)
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
func (i *iptables) addExternalACLs(cfg *ACLInfo, chain string, reverseChain string, rules []aclIPset, isAppAcls bool) error {

	rulesBucket := i.sortACLsInBuckets(cfg, chain, reverseChain, rules, isAppAcls)

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
func (i *iptables) deleteChainRules(cfg *ACLInfo) error {

	if i.mode != constants.LocalServer {
		return i.processRulesFromList(i.containerChainRules(cfg), "Delete")
	}

	if cfg.UID != "" {
		return i.processRulesFromList(i.uidChainRules(cfg), "Delete")
	}

	return i.processRulesFromList(i.cgroupChainRules(cfg), "Delete")
}

// deletePUChains removes all the container specific chains and basic rules
func (i *iptables) deletePUChains(appChain, netChain string) error {

	if err := i.impl.ClearChain(appPacketIPTableContext, appChain); err != nil {
		zap.L().Warn("Failed to clear the container ack packets chain",
			zap.String("appChain", appChain),
			zap.String("context", appPacketIPTableContext),
			zap.Error(err),
		)
	}

	if err := i.impl.DeleteChain(appPacketIPTableContext, appChain); err != nil {
		zap.L().Warn("Failed to delete the container ack packets chain",
			zap.String("appChain", appChain),
			zap.String("context", appPacketIPTableContext),
			zap.Error(err),
		)
	}

	if err := i.impl.ClearChain(netPacketIPTableContext, netChain); err != nil {
		zap.L().Warn("Failed to clear the container net packets chain",
			zap.String("netChain", netChain),
			zap.String("context", netPacketIPTableContext),
			zap.Error(err),
		)
	}

	if err := i.impl.DeleteChain(netPacketIPTableContext, netChain); err != nil {
		zap.L().Warn("Failed to delete the container net packets chain",
			zap.String("netChain", netChain),
			zap.String("context", netPacketIPTableContext),
			zap.Error(err),
		)
	}

	return nil
}

// setGlobalRules installs the global rules
func (i *iptables) setGlobalRules() error {

	cfg, err := i.newACLInfo(0, "", nil, 0)
	if err != nil {
		return err
	}
	ipsetPrefix := i.impl.GetIPSetPrefix()

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
	err = i.impl.Insert(appProxyIPTableContext,
		ipTableSectionPreRouting, 1,
		"-p", "tcp",
		"-m", "addrtype", "--dst-type", "LOCAL",
		"-m", "set", "!", "--match-set", ipsetPrefix+excludedNetworkSet, "src",
		"-j", natProxyInputChain)
	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at net: %s", err)
	}

	err = i.impl.Insert(appProxyIPTableContext,
		ipTableSectionOutput, 1,
		"-m", "set", "!", "--match-set", ipsetPrefix+excludedNetworkSet, "dst",
		"-j", natProxyOutputChain)
	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at net: %s", err)
	}

	return nil
}

// removeGlobalHooksPre is called before we jump into template driven rules.This is best effort
// no errors if these things fail.
func (i *iptables) removeGlobalHooksPre() {
	rules := [][]string{
		{
			"nat",
			"PREROUTING",
			"-p", "tcp",
			"-m", "addrtype",
			"--dst-type", "LOCAL",
			"-m", "set", "!", "--match-set", "TRI-Excluded", "src",
			"-j", "TRI-Redir-Net",
		},
		{
			"nat",
			"OUTPUT",
			"-m", "set", "!", "--match-set", "TRI-Excluded", "dst",
			"-j", "TRI-Redir-App",
		},
	}

	for _, rule := range rules {
		if err := i.impl.Delete(rule[0], rule[1], rule[2:]...); err != nil {
			zap.L().Debug("Error while delete rules", zap.Strings("rule", rule))
		}
	}

}
func (i *iptables) removeGlobalHooks(cfg *ACLInfo) error {
	// This func is a chance to remove rules that don't fit in your templates.
	// This should ideally not be used
	i.removeGlobalHooksPre()

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

func (i *iptables) cleanACLs() error { // nolint
	cfg, err := i.newACLInfo(0, "", nil, 0)
	if err != nil {
		return err
	}

	// First clear the nat rules
	if err := i.removeGlobalHooks(cfg); err != nil {
		zap.L().Error("unable to remove nat proxy rules")
	}

	// Clean Application Rules/Chains
	i.cleanACLSection(appPacketIPTableContext, chainPrefix)
	i.cleanACLSection(appProxyIPTableContext, chainPrefix)

	i.impl.Commit() // nolint

	// Always return nil here. No reason to block anything if cleans fail.
	return nil
}

// cleanACLSection flushes and deletes all chains with Prefix - Trireme
func (i *iptables) cleanACLSection(context, chainPrefix string) {

	rules, err := i.impl.ListChains(context)
	if err != nil {
		zap.L().Warn("Failed to list chains",
			zap.String("context", context),
			zap.Error(err),
		)
	}

	for _, rule := range rules {
		if strings.Contains(rule, chainPrefix) {
			if err := i.impl.ClearChain(context, rule); err != nil {
				zap.L().Warn("Can not clear the chain",
					zap.String("context", context),
					zap.String("section", rule),
					zap.Error(err),
				)
			}
		}
	}

	for _, rule := range rules {
		if strings.Contains(rule, chainPrefix) {
			if err := i.impl.DeleteChain(context, rule); err != nil {
				zap.L().Warn("Can not delete the chain",
					zap.String("context", context),
					zap.String("section", rule),
					zap.Error(err),
				)
			}
		}
	}
}
