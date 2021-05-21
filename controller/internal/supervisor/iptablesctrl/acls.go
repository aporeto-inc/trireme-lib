package iptablesctrl

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/template"

	"github.com/kballard/go-shellquote"
	"github.com/mattn/go-shellwords"
	mgrconstants "go.aporeto.io/cns-agent-mgr/pkg/constants"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	markconstants "go.aporeto.io/enforcerd/trireme-lib/utils/constants"
	"go.aporeto.io/gaia/protocols"
	"go.uber.org/zap"
)

const (
	numPackets   = "100"
	initialCount = "99"
)

var (
	cnsAgentBootPid    int
	cnsAgentMgrPid     int
	getEnforcerPID     = func() int { return os.Getpid() }
	getCnsAgentMgrPID  = func() int { return cnsAgentMgrPid }
	getCnsAgentBootPID = func() int { return cnsAgentBootPid }
)

func init() {
	cnsAgentBootPid = -1
	if mgrconstants.IsManagedByCnsAgentManager() {
		cnsAgentBootPid = discoverCnsAgentBootPID()
	}
	cnsAgentMgrPid = -1
	if mgrconstants.IsManagedByCnsAgentManager() {
		cnsAgentMgrPid = os.Getppid()
	}
}

type rulesInfo struct {
	RejectObserveApply    [][]string
	RejectNotObserved     [][]string
	RejectObserveContinue [][]string

	AcceptObserveApply    [][]string
	AcceptNotObserved     [][]string
	AcceptObserveContinue [][]string
	ReverseRules          [][]string
}

// cgroupChainRules provides the rules for redirecting to a processing unit
// specific chain based for Linux processed and based on the cgroups and net_cls
// configuration.
func (i *iptables) cgroupChainRules(cfg *ACLInfo) [][]string {

	if legacyRules, ok := i.legacyPuChainRules(cfg); ok {
		return legacyRules
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
		"isProcessPU": func() bool {
			return cfg.PUType == common.LinuxProcessPU || cfg.PUType == common.WindowsProcessPU
		},
		"isIPV6Enabled": func() bool {
			// icmpv6 rules are needed for ipv6
			return cfg.needICMPRules
		},
	}).Parse(cgroupCaptureTemplate))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}
	rules = append(rules, i.proxyRules(cfg)...)
	rules = append(rules, i.proxyDNSRules(cfg)...)
	return rules
}

// containerChainRules provides the list of rules that are used to send traffic to
// a particular chain
func (i *iptables) containerChainRules(cfg *ACLInfo) [][]string {
	tmpl := template.Must(template.New(containerChainTemplate).Parse(containerChainTemplate))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}
	rules = append(rules, i.istioRules(cfg)...)
	if i.serviceMeshType == policy.None {
		rules = append(rules, i.proxyRules(cfg)...)
	}
	rules = append(rules, i.proxyDNSRules(cfg)...)
	return rules
}

func (i *iptables) istioRules(cfg *ACLInfo) [][]string {
	if i.serviceMeshType == policy.Istio {
		tmpl := template.Must(template.New(istioChainTemplate).Funcs(template.FuncMap{
			"IstioUID": func() string {
				return IstioUID
			},
		}).Parse(istioChainTemplate))
		rules, err := extractRulesFromTemplate(tmpl, cfg)
		if err != nil {
			zap.L().Warn("unable to extract rules", zap.Error(err))
		}
		zap.L().Debug("configured Istio: ", zap.Any(" rules ", rules))
		return rules
	}
	return nil
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

func (i *iptables) proxyDNSRules(cfg *ACLInfo) [][]string {
	tmpl := template.Must(template.New(proxyDNSChainTemplate).Funcs(template.FuncMap{
		"isCgroupSet": func() bool {
			return cfg.CgroupMark != ""
		},
		"enableDNSProxy": func() bool {
			return cfg.DNSServerIP != ""
		},
	}).Parse(proxyDNSChainTemplate))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("proxyDNSRules unable to extract rules", zap.Error(err))
	}
	return rules
}

// extractPreNetworkACLRules creates the rules that come before ACL rules.
func (i *iptables) extractPreNetworkACLRules(cfg *ACLInfo) [][]string {

	tmpl := template.Must(template.New(preNetworkACLRuleTemplate).Funcs(template.FuncMap{
		"Increment": func(i int) int {
			return i + 1
		},
	}).Parse(preNetworkACLRuleTemplate))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}
	return rules
}

// trapRules provides the packet capture rules that are defined for each processing unit.
func (i *iptables) trapRules(cfg *ACLInfo, isHostPU bool, appAnyRules, netAnyRules [][]string) [][]string {

	outputMark, _ := strconv.Atoi(cfg.PacketMark)
	outputMark = outputMark * cfg.NumNFQueues

	tmpl := template.Must(template.New(packetCaptureTemplate).Funcs(template.FuncMap{
		"windowsAllIpsetName": func() string {
			return i.ipsetmanager.GetIPsetPrefix() + "WindowsAllIPs"
		},
		"packetMark": func() string {
			outputMark, _ := strconv.Atoi(cfg.PacketMark)
			outputMark = outputMark * cfg.NumNFQueues
			return strconv.Itoa(outputMark)
		},
		"getOutputMark": func() string {
			m := strconv.Itoa(outputMark)
			outputMark++
			return m
		},
		"queueBalance": func() string {
			return fmt.Sprintf("0:%d", cfg.NumNFQueues-1)
		},
		"isNotContainerPU": func() bool {
			return cfg.PUType != common.ContainerPU
		},
		"needDnsRules": func() bool {
			return isHostPU
		},
		"needICMP": func() bool {
			return cfg.needICMPRules
		},
		"appAnyRules": func() [][]string {
			return appAnyRules
		},
		"netAnyRules": func() [][]string {
			return netAnyRules
		},
		"joinRule": func(rule []string) string {
			return strings.Join(rule, " ")
		},
		"isBPFEnabled": func() bool {
			return i.bpf != nil
		},
		"isHostPU": func() bool {
			return isHostPU
		},
		"Increment": func(i int) int {
			return i + 1
		},
		"isAppDrop": func() bool {
			return strings.EqualFold(cfg.AppDefaultAction, "DROP")
		},
		"isNetDrop": func() bool {
			return strings.EqualFold(cfg.NetDefaultAction, "DROP")
		},
	}).Parse(packetCaptureTemplate))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}

	return rules
}

// getProtocolAnyRules returns app any acls and net any acls.
func (i *iptables) getProtocolAnyRules(cfg *ACLInfo, appRules, netRules []aclIPset) ([][]string, [][]string, error) {

	appAnyRules, _ := extractProtocolAnyRules(appRules)
	netAnyRules, _ := extractProtocolAnyRules(netRules)

	sortedAppAnyRulesBuckets := i.sortACLsInBuckets(cfg, cfg.AppChain, cfg.NetChain, appAnyRules, true)
	sortedNetAnyRulesBuckets := i.sortACLsInBuckets(cfg, cfg.NetChain, cfg.AppChain, netAnyRules, false)

	sortedAppAnyRules, err := extractACLsFromTemplate(sortedAppAnyRulesBuckets)
	if err != nil {
		return nil, nil, fmt.Errorf("unable extract app protocol any rules: %v", err)
	}

	sortedNetAnyRules, err := extractACLsFromTemplate(sortedNetAnyRulesBuckets)
	if err != nil {
		return nil, nil, fmt.Errorf("unable extract net protocol any rules: %v", err)
	}

	sortedAppAnyRules = transformACLRules(sortedAppAnyRules, cfg, sortedAppAnyRulesBuckets, true)
	sortedNetAnyRules = transformACLRules(sortedNetAnyRules, cfg, sortedNetAnyRulesBuckets, false)

	return sortedAppAnyRules, sortedNetAnyRules, nil
}

func extractACLsFromTemplate(rulesBucket *rulesInfo) ([][]string, error) {

	tmpl := template.Must(template.New(acls).Funcs(template.FuncMap{
		"joinRule": func(rule []string) string {
			return shellquote.Join(rule...)
		},
	}).Parse(acls))

	aclRules, err := extractRulesFromTemplate(tmpl, *rulesBucket)
	if err != nil {
		return nil, fmt.Errorf("unable to extract rules from template: %s", err)
	}

	return aclRules, nil
}

// extractProtocolAnyRules extracts protocol any rules from the set and returns
// protocol any rules and all other rules without any.
func extractProtocolAnyRules(rules []aclIPset) (anyRules []aclIPset, otherRules []aclIPset) {

	for _, rule := range rules {
		for _, proto := range rule.Protocols {

			if proto != constants.AllProtoString {
				otherRules = append(otherRules, rule)
				continue
			}

			anyRules = append(anyRules, rule)
		}
	}

	return anyRules, otherRules
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

	return i.processRulesFromList(i.cgroupChainRules(cfg), "Append")
}

// addPacketTrap adds the necessary iptables rules to capture control packets to user space
func (i *iptables) addPacketTrap(cfg *ACLInfo, isHostPU bool, appAnyRules, netAnyRules [][]string) error {

	return i.processRulesFromList(i.trapRules(cfg, isHostPU, appAnyRules, netAnyRules), "Append")
}

// programExtensionsRules programs iptable rules for the given extensions
func (i *iptables) programExtensionsRules(contextID string, rule *aclIPset, chain, proto, ipMatchDirection, nfLogGroup string) error {

	rulesspec := []string{
		"-p", proto,
		"-m", "set", "--match-set", rule.ipset, ipMatchDirection,
	}

	for _, ext := range rule.Extensions {
		if rule.Policy.Action&policy.Log > 0 {
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
		"-j", "NFLOG", "--nflog-group", nfLogGroup, "--nflog-prefix", rule.Policy.LogPrefixAction(contextID, action)}
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

		for _, proto := range rule.Protocols {

			if !i.impl.ProtocolAllowed(proto) {
				continue
			}

			if i.aclSkipProto(proto) {
				continue
			}

			acls, r := i.generateACLRules(cfg, &rule, chain, reverseChain, nflogGroup, proto, direction, reverse, isAppACLs)
			rulesBucket.ReverseRules = append(rulesBucket.ReverseRules, r...)

			if testReject(rule.Policy) && testObserveApply(rule.Policy) {
				rulesBucket.RejectObserveApply = append(rulesBucket.RejectObserveApply, acls...)
			}

			if testReject(rule.Policy) && testNotObserved(rule.Policy) {
				rulesBucket.RejectNotObserved = append(rulesBucket.RejectNotObserved, acls...)
			}

			if testReject(rule.Policy) && testObserveContinue(rule.Policy) {
				rulesBucket.RejectObserveContinue = append(rulesBucket.RejectObserveContinue, acls...)
			}

			if testAccept(rule.Policy) && testObserveContinue(rule.Policy) {
				rulesBucket.AcceptObserveContinue = append(rulesBucket.AcceptObserveContinue, acls...)
			}

			if testAccept(rule.Policy) && testNotObserved(rule.Policy) {
				rulesBucket.AcceptNotObserved = append(rulesBucket.AcceptNotObserved, acls...)
			}

			if testAccept(rule.Policy) && testObserveApply(rule.Policy) {
				rulesBucket.AcceptObserveApply = append(rulesBucket.AcceptObserveApply, acls...)
			}
		}
	}

	return rulesBucket
}

// addExternalACLs adds a set of rules to the external services that are initiated
// by an application. The allow rules are inserted with highest priority.
func (i *iptables) addExternalACLs(cfg *ACLInfo, chain string, reverseChain string, rules []aclIPset, isAppAcls bool) error {

	_, rules = extractProtocolAnyRules(rules)

	rulesBucket := i.sortACLsInBuckets(cfg, chain, reverseChain, rules, isAppAcls)

	aclRules, err := extractACLsFromTemplate(rulesBucket)
	if err != nil {
		return fmt.Errorf("unable to extract rules from template: %s", err)
	}

	aclRules = transformACLRules(aclRules, cfg, rulesBucket, isAppAcls)

	if err := i.processRulesFromList(aclRules, "Append"); err != nil {
		return fmt.Errorf("unable to install rules - mode :%s %v", err, isAppAcls)
	}

	return nil
}

func (i *iptables) addPreNetworkACLRules(cfg *ACLInfo) error {

	rules := i.extractPreNetworkACLRules(cfg)

	if err := i.processRulesFromList(rules, "Append"); err != nil {
		return fmt.Errorf("unable to install networkd SYN rule : %s", err)
	}

	return nil
}

// deleteChainRules deletes the rules that send traffic to our chain
func (i *iptables) deleteChainRules(cfg *ACLInfo) error {

	if i.mode != constants.LocalServer {
		return i.processRulesFromList(i.containerChainRules(cfg), "Delete")
	}

	return i.processRulesFromList(i.cgroupChainRules(cfg), "Delete")
}

// setGlobalRules installs the global rules
func (i *iptables) setGlobalRules() error {
	cfg, err := i.newACLInfo(0, "", nil, 0)
	if err != nil {
		return err
	}

	_, _, excludedNetworkName := i.ipsetmanager.GetIPsetNamesForTargetAndExcludedNetworks()

	inputMark, _ := strconv.Atoi(cfg.DefaultInputMark) //nolint
	outputMark := 0

	tmpl := template.Must(template.New(globalRules).Funcs(template.FuncMap{
		"isIstioEnabled": func() bool {
			return i.serviceMeshType == policy.Istio
		},
		"IstioRedirPort": func() string {
			return IstioRedirPort
		},
		"getInputMark": func() string {
			m := strconv.Itoa(inputMark)
			inputMark++
			return m
		},
		"getOutputMark": func() string {
			m := strconv.Itoa(outputMark)
			outputMark++
			return m
		},
		"queueBalance": func() string {
			return fmt.Sprintf("0:%d", cfg.NumNFQueues-1)
		},
		"isLocalServer": func() bool {
			return i.mode == constants.LocalServer
		},
		"isBPFEnabled": func() bool {
			return i.bpf != nil
		},
		"enableDNSProxy": func() bool {
			return cfg.DNSServerIP != ""
		},
		"Increment": func(i int) int {
			return i + 1
		},
		"EnforcerPID": func() string {
			return strconv.Itoa(getEnforcerPID())
		},
		"CnsAgentMgrPID": func() string {
			return strconv.Itoa(getCnsAgentMgrPID())
		},
		"CnsAgentBootPID": func() string {
			return strconv.Itoa(getCnsAgentBootPID())
		},
		"isManagedByCnsAgentManager": func() bool {
			return getCnsAgentBootPID() > 0
		},
		"isIPv4": func() bool {
			return i.impl.IPVersion() == IPV4
		},
		"windowsDNSServerName": func() string {
			return i.ipsetmanager.GetIPsetPrefix() + "WindowsDNSServer"
		},
		"isKubernetesPU": func() bool {
			return cfg.PUType == common.KubernetesPU
		},
		"needICMP": func() bool {
			return cfg.needICMPRules
		},
	}).Parse(globalRules))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}

	if err := i.processRulesFromList(rules, "Append"); err != nil {
		return fmt.Errorf("unable to install global rules:%s", err)
	}

	// Insert the Istio nat rules into the ISTIO_OUTPUT table
	// the following is done so that there is no loop in the dataPath.
	// basically, the envoy packets which are already processed by us, we should
	// accept the packets.
	if i.serviceMeshType == policy.Istio {
		err = i.impl.Insert(appProxyIPTableContext,
			ipTableSectionOutput, 1,
			"-p", "tcp",
			"-m", "mark", "--mark", strconv.Itoa(markconstants.IstioPacketMark),
			"-j", "ACCEPT")
		if err != nil {
			return fmt.Errorf("unable to add Istio accept for marked packets : %s", err)
		}
	}

	// nat rules cannot be templated, since they interfere with Docker.
	err = i.impl.Insert(appProxyIPTableContext,
		ipTableSectionPreRouting, 1,
		"-p", "tcp",
		"-m", "addrtype", "--dst-type", "LOCAL",
		"-m", "set", "!", "--match-set", excludedNetworkName, "src",
		"-j", natProxyInputChain)
	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at net: %s", err)
	}

	err = i.impl.Insert(appProxyIPTableContext,
		ipTableSectionOutput, 1,
		"-m", "set", "!", "--match-set", excludedNetworkName, "dst",
		"-j", natProxyOutputChain)
	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at net: %s", err)
	}

	return nil
}

func (i *iptables) removeGlobalHooks(cfg *ACLInfo) error {

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

func (i *iptables) generateACLRules(cfg *ACLInfo, rule *aclIPset, chain string, reverseChain string, nfLogGroup, proto, ipMatchDirection string, reverseDirection string, isAppACLs bool) ([][]string, [][]string) {

	iptRules := [][]string{}
	reverseRules := [][]string{}

	targetTCPName, targetUDPName, _ := i.ipsetmanager.GetIPsetNamesForTargetAndExcludedNetworks()

	observeContinue := rule.Policy.ObserveAction.ObserveContinue()
	contextID := cfg.ContextID

	baseRule := func(proto string) []string {

		iptRule := []string{appPacketIPTableContext, chain}

		if splits := strings.Split(proto, "/"); strings.ToUpper(splits[0]) == protocols.L4ProtocolICMP || strings.ToUpper(splits[0]) == protocols.L4ProtocolICMP6 {
			iptRule = append(iptRule, icmpRule(proto, rule.Ports)...)

			if strings.ToUpper(splits[0]) == protocols.L4ProtocolICMP6 {
				proto = "icmpv6"
			} else {
				proto = "icmp"
			}
		}

		iptRule = append(iptRule, []string{
			"-p", proto,
			"-m", "set", "--match-set", rule.ipset, ipMatchDirection,
		}...)

		if proto == constants.UDPProtoNum || proto == constants.UDPProtoString {
			udpRule := generateUDPACLRule()
			iptRule = append(iptRule, udpRule...)
		}

		if proto == constants.TCPProtoNum || proto == constants.TCPProtoString {
			stateMatch := []string{"-m", "state", "--state", "NEW"}
			iptRule = append(iptRule, stateMatch...)
		}

		// add the target network condition if tcp and not a reject action and is the app chain
		if (rule.Policy.Action&policy.Reject == 0 && isAppACLs) && (proto == constants.TCPProtoNum || proto == constants.TCPProtoString) {
			targetNet := []string{"-m", "set", "!", "--match-set", targetTCPName, ipMatchDirection}
			iptRule = append(iptRule, targetNet...)
		}

		// add the target network condition if tcp and not a reject action and is the app chain
		if (rule.Policy.Action&policy.Reject == 0 && isAppACLs) && (proto == constants.UDPProtoNum || proto == constants.UDPProtoString) {

			targetUDPClause := targetUDPNetworkClause(rule, targetUDPName, ipMatchDirection)
			if len(targetUDPClause) > 0 {
				iptRule = append(iptRule, targetUDPClause...)
			}

		}
		// port match is required only for tcp and udp protocols
		if proto == constants.TCPProtoNum || proto == constants.UDPProtoNum || proto == constants.TCPProtoString || proto == constants.UDPProtoString {

			portMatchSet := []string{"--match", "multiport", "--dports", strings.Join(rule.Ports, ",")}
			iptRule = append(iptRule, portMatchSet...)
		}

		return iptRule
	}

	if err := i.programExtensionsRules(contextID, rule, chain, proto, ipMatchDirection, nfLogGroup); err != nil {
		zap.L().Warn("unable to program extension rules",
			zap.Error(err),
		)
	}

	// If log or observeContinue
	if rule.Policy.Action&policy.Log != 0 || observeContinue {
		state := []string{}
		if proto == constants.TCPProtoNum || proto == constants.UDPProtoNum || proto == constants.TCPProtoString || proto == constants.UDPProtoString {
			state = []string{"-m", "state", "--state", "NEW"}
		}

		nflog := append(state, []string{"-j", "NFLOG", "--nflog-group", nfLogGroup, "--nflog-prefix", rule.Policy.LogPrefix(contextID)}...)
		nfLogRule := append(baseRule(proto), nflog...)

		iptRules = append(iptRules, nfLogRule)
	}

	if !observeContinue {
		if (rule.Policy.Action & policy.Accept) != 0 {
			if proto == constants.UDPProtoNum || proto == constants.UDPProtoString {
				connmarkClause := connmarkUDPConnmarkClause()
				if len(connmarkClause) > 0 {
					connmarkRule := append(baseRule(proto), connmarkClause...)
					iptRules = append(iptRules, connmarkRule)
				}
			}
			acceptRule := append(baseRule(proto), []string{"-j", "ACCEPT"}...)
			iptRules = append(iptRules, acceptRule)
		}

		if rule.Policy.Action&policy.Reject != 0 {
			reject := []string{"-j", "DROP"}
			rejectRule := append(baseRule(proto), reject...)
			iptRules = append(iptRules, rejectRule)
		}

		if rule.Policy.Action&policy.Accept != 0 && (proto == constants.UDPProtoNum || proto == constants.UDPProtoString) {
			reverseRules = append(reverseRules, []string{
				appPacketIPTableContext,
				reverseChain,
				"-p", proto,
				"-m", "set", "--match-set", rule.ipset, reverseDirection,
				"-m", "state", "--state", "ESTABLISHED",
				"-m", "connmark", "--mark", strconv.Itoa(int(markconstants.DefaultExternalConnMark)),
				"-j", "ACCEPT",
			})
		}
	}

	return iptRules, reverseRules
}
