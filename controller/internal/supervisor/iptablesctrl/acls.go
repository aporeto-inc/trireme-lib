package iptablesctrl

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/template"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cgnetcls"
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
}

func (i *Instance) puChainRules(contextID, appChain string, netChain string, mark string, tcpPortSet, tcpPorts, udpPorts string, proxyPort string, proxyPortSetName string,
	appSection, netSection string) [][]string {

	aclInfo := ACLInfo{
		MangleTable: i.appPacketIPTableContext,
		AppSection:  appSection,
		NetSection:  netSection,
		AppChain:    appChain,
		NetChain:    netChain,
		Mark:        mark,
		NFLOGPrefix: policy.DefaultAcceptLogPrefix(contextID),
		TCPPorts:    tcpPorts,
		UDPPorts:    udpPorts,
		TCPPortSet:  tcpPortSet,
	}

	tmpl := template.Must(template.New(cgroupRules).Funcs(template.FuncMap{
		"isUDPPorts": func() bool {
			return udpPorts != "0"
		},
		"isTCPPorts": func() bool {
			return tcpPorts != "0"
		},
		"isHostPU": func() bool {
			return appSection == HostModeOutput && netSection == HostModeInput
		},
	}).Parse(cgroupRules))

	rules, err := extractRulesFromTemplate(tmpl, aclInfo)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}

	return append(rules, i.proxyRules(proxyPort, proxyPortSetName, mark)...)
}

func (i *Instance) cgroupChainRules(contextID, appChain string, netChain string, mark string, tcpPortSet, tcpPorts, udpPorts string, proxyPort string, proxyPortSetName string,
	appSection, netSection string, puType string) [][]string {

	// Rules for older distros (eg RH 6.9/Ubuntu 14.04), due to absence of
	// cgroup match modules, source ports are used  to trap outgoing traffic.
	if i.isLegacyKernel && (puType == extractors.HostModeNetworkPU || puType == extractors.HostPU) {
		return i.legacyPuChainRules(contextID, appChain, netChain, mark, tcpPorts, udpPorts, proxyPort, proxyPortSetName,
			appSection, netSection, puType)
	}

	return i.puChainRules(contextID, appChain, netChain, mark, tcpPortSet, tcpPorts, udpPorts, proxyPort, proxyPortSetName,
		appSection, netSection)
}

func (i *Instance) uidChainRules(tcpPorts, portSetName, appChain string, netChain string, mark string, uid string, proxyPort string, proxyPortSetName string) [][]string {

	aclInfo := ACLInfo{
		MangleTable: i.appPacketIPTableContext,
		PreRouting:  ipTableSectionPreRouting,
		AppChain:    appChain,
		NetChain:    netChain,
		Mark:        mark,
		PortSet:     portSetName,
		UID:         uid,
	}

	tmpl := template.Must(template.New(uidPuRules).Parse(uidPuRules))

	rules, err := extractRulesFromTemplate(tmpl, aclInfo)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}

	if i.isLegacyKernel {
		return append(rules, i.legacyProxyRules(tcpPorts, proxyPort, proxyPortSetName, mark)...)
	}
	return append(rules, i.proxyRules(proxyPort, proxyPortSetName, mark)...)
}

// chainRules provides the list of rules that are used to send traffic to
// a particular chain
func (i *Instance) chainRules(contextID string, appChain string, netChain string, proxyPort string, proxyPortSetName string) [][]string {

	aclInfo := ACLInfo{
		MangleTable: i.appPacketIPTableContext,
		AppSection:  i.appPacketIPTableSection,
		NetSection:  i.netPacketIPTableSection,
		AppChain:    appChain,
		NetChain:    netChain,
		NFLOGPrefix: policy.DefaultAcceptLogPrefix(contextID),
	}

	tmpl := template.Must(template.New(containerPuRules).Parse(containerPuRules))

	rules, err := extractRulesFromTemplate(tmpl, aclInfo)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}

	return append(rules, i.proxyRules(proxyPort, proxyPortSetName, "")...)
}

// proxyRules creates all the proxy specific rules.
func (i *Instance) proxyRules(proxyPort string, proxyPortSetName string, cgroupMark string) [][]string {
	destSetName, srvSetName := i.getSetNames(proxyPortSetName)

	aclInfo := ACLInfo{
		MangleTable:         i.appPacketIPTableContext,
		NatTable:            i.appProxyIPTableContext,
		MangleProxyAppChain: proxyOutputChain,
		MangleProxyNetChain: proxyInputChain,
		NatProxyNetChain:    natProxyInputChain,
		NatProxyAppChain:    natProxyOutputChain,
		CgroupMark:          cgroupMark,
		DestIPSet:           destSetName,
		SrvIPSet:            srvSetName,
		ProxyPort:           proxyPort,
		ProxyMark:           proxyMark,
	}

	tmpl := template.Must(template.New(proxyChainRules).Funcs(template.FuncMap{
		"isCgroupSet": func() bool {
			return cgroupMark != ""
		},
	}).Parse(proxyChainRules))

	rules, err := extractRulesFromTemplate(tmpl, aclInfo)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}
	return rules
}

//trapRules provides the packet trap rules to add/delete
func (i *Instance) trapRules(contextID, appChain string, netChain string, isHostPU bool) [][]string {

	aclInfo := ACLInfo{
		MangleTable:        i.appPacketIPTableContext,
		AppChain:           appChain,
		NetChain:           netChain,
		QueueBalanceNetSyn: i.fqc.GetNetworkQueueSynStr(),
		QueueBalanceNetAck: i.fqc.GetNetworkQueueAckStr(),
		QueueBalanceAppSyn: i.fqc.GetApplicationQueueSynStr(),
		QueueBalanceAppAck: i.fqc.GetApplicationQueueAckStr(),
		TargetNetSet:       targetNetworkSet,
		Numpackets:         numPackets,
		InitialCount:       initialCount,
		NFLOGPrefix:        policy.DefaultLogPrefix(contextID),
	}

	tmpl := template.Must(template.New(trapRules).Funcs(template.FuncMap{
		"needDnsRules": func() bool {
			return i.mode == constants.Sidecar || isHostPU || i.isLegacyKernel
		},
	}).Parse(trapRules))

	rules, err := extractRulesFromTemplate(tmpl, aclInfo)
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
				zap.L().Warn("Unable to delete rule from chain", zap.Error(err))

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

// addUDPNatRule adds a rule to avoid masquarading traffic from host udp servers.
func (i *Instance) getUDPNatRule(udpPorts string, insert bool) [][]string {

	rules := [][]string{}
	if insert {
		rules = append(rules, []string{
			"nat",
			"POSTROUTING",
			"1",
			"-p", udpProto,
			"-m", "addrtype", "--src-type", "LOCAL",
			"-m", "multiport",
			"--source-ports", udpPorts,
			"-j", "ACCEPT",
		})
	} else {
		rules = append(rules, []string{
			"nat",
			"POSTROUTING",
			"-p", udpProto,
			"-m", "addrtype", "--src-type", "LOCAL",
			"-m", "multiport",
			"--source-ports", udpPorts,
			"-j", "ACCEPT",
		})
	}
	return rules
}

// addChainrules implements all the iptable rules that redirect traffic to a chain
func (i *Instance) addChainRules(contextID string, portSetName string, appChain string, netChain string, tcpPorts, udpPorts string, mark string, uid string, proxyPort string, proxyPortSetName string, puType string) error {
	if i.mode == constants.LocalServer {
		if uid == "" {
			if udpPorts != "0" {
				// Add a postrouting Nat rule for udp to not masquarade udp traffic for host servers.
				err := i.processRulesFromList(i.getUDPNatRule(udpPorts, true), "Insert")
				if err != nil {
					return fmt.Errorf("Unable to add nat rule for udp: %s", err)
				}
			}

			// choose correct chains based on puType
			appSection := ""
			netSection := ""
			switch puType {
			case extractors.LinuxPU:
				appSection = TriremeOutput
				netSection = TriremeInput
			case extractors.HostModeNetworkPU:
				appSection = NetworkSvcOutput
				netSection = NetworkSvcInput
			case extractors.HostPU:
				appSection = HostModeOutput
				netSection = HostModeInput
			default:
				appSection = TriremeOutput
				netSection = TriremeInput
			}

			return i.processRulesFromList(i.cgroupChainRules(contextID, appChain, netChain, mark, portSetName, tcpPorts, udpPorts, proxyPort, proxyPortSetName, appSection, netSection, puType), "Append")
		}

		return i.processRulesFromList(i.uidChainRules(tcpPorts, portSetName, appChain, netChain, mark, uid, proxyPort, proxyPortSetName), "Append")
	}

	return i.processRulesFromList(i.chainRules(contextID, appChain, netChain, proxyPort, proxyPortSetName), "Append")
}

// addPacketTrap adds the necessary iptables rules to capture control packets to user space
func (i *Instance) addPacketTrap(contextID, appChain string, netChain string, isHostPU bool) error {

	return i.processRulesFromList(i.trapRules(contextID, appChain, netChain, isHostPU), "Append")

}

func (i *Instance) getRules(contextID string, rule *aclIPset, insertOrder *int, chain string, nfLogGroup, proto, ipMatchDirection, order string) [][]string {
	iptRules := [][]string{}
	observeContinue := rule.policy.ObserveAction.ObserveContinue()

	baseRule := func(insertOrder int, proto string) []string {
		iptRule := []string{
			i.appPacketIPTableContext,
			chain,
			strconv.Itoa(insertOrder),
			"-p", proto,
			"-m", "set", "--match-set", rule.ipset, ipMatchDirection}

		// only tcp uses target networks
		if proto == constants.TCPProtoNum {
			targetNet := []string{"-m", "set", "!", "--match-set", targetNetworkSet, ipMatchDirection}
			iptRule = append(iptRule, targetNet...)
		}

		// port match is required only for tcp and udp protocols
		if proto == constants.TCPProtoNum || proto == constants.UDPProtoNum {
			portMatchSet := []string{"--match", "multiport", "--dports", strings.Join(rule.ports, ",")}
			iptRule = append(iptRule, portMatchSet...)
		}

		return iptRule
	}

	if rule.policy.Action&policy.Log > 0 || observeContinue {
		nflog := []string{"-m", "state", "--state", "NEW",
			"-j", "NFLOG", "--nflog-group", nfLogGroup, "--nflog-prefix", rule.policy.LogPrefix(contextID)}
		nfLogRule := append(baseRule(*insertOrder, proto), nflog...)

		*insertOrder++
		iptRules = append(iptRules, nfLogRule)
	}

	if !observeContinue {
		if (rule.policy.Action & policy.Accept) != 0 {
			accept := []string{"-j", "ACCEPT"}
			acceptRule := append(baseRule(*insertOrder, proto), accept...)

			*insertOrder++
			iptRules = append(iptRules, acceptRule)
		}

		if rule.policy.Action&policy.Reject != 0 {
			reject := []string{"-j", "DROP"}
			rejectRule := append(baseRule(*insertOrder, proto), reject...)

			*insertOrder++
			iptRules = append(iptRules, rejectRule)
		}
	}

	if order == "Append" {
		// remove the insertion order from rules
		for i, rule := range iptRules {
			iptRules[i] = append(rule[:2], rule[3:]...)
		}
		return iptRules
	}
	return iptRules
}

func (i *Instance) addAllAppACLS(contextID, appChain, netChain string, rules []aclIPset, rulesBucket *rulesInfo) {

	insertOrder := int(1)
	intP := &insertOrder

	testObserveContinue := func(p *policy.FlowPolicy) bool {
		return p.ObserveAction.ObserveContinue()
	}

	testNotObserved := func(p *policy.FlowPolicy) bool {
		return !p.ObserveAction.Observed()
	}

	testObserveApply := func(p *policy.FlowPolicy) bool {
		return p.ObserveAction.ObserveApply()
	}

	testReject := func(p *policy.FlowPolicy) bool {
		return (p.Action&policy.Reject != 0)
	}

	testAccept := func(p *policy.FlowPolicy) bool {
		return (p.Action&policy.Accept != 0)
	}

	for _, rule := range rules {

		for _, proto := range rule.protocols {

			appACLS := i.getRules(contextID, &rule, intP, appChain, "10", proto, "dst", "Append")

			if testReject(rule.policy) && testObserveApply(rule.policy) {
				rulesBucket.RejectObserveApply = append(rulesBucket.RejectObserveApply,
					appACLS...)

				if (rule.policy.Action&policy.Accept) != 0 && (proto == constants.UDPProtoNum) {
					// Add a corresponding rule at the top of netChain.
					rulesBucket.RejectObserveApply = append(rulesBucket.RejectObserveApply, []string{
						i.appPacketIPTableContext, netChain,
						"-p", proto,
						"-m", "set", "--match-set", rule.ipset, "src",
						"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
						"-m", "state", "--state", "ESTABLISHED",
						"-j", "ACCEPT",
					})
				}
			}

			if testReject(rule.policy) && testNotObserved(rule.policy) {
				rulesBucket.RejectNotObserved = append(rulesBucket.RejectNotObserved,
					appACLS...)

				if (rule.policy.Action&policy.Accept) != 0 && (proto == constants.UDPProtoNum) {
					// Add a corresponding rule at the top of netChain.
					rulesBucket.RejectNotObserved = append(rulesBucket.RejectNotObserved, []string{
						i.appPacketIPTableContext, netChain,
						"-p", proto,
						"-m", "set", "--match-set", rule.ipset, "src",
						"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
						"-m", "state", "--state", "ESTABLISHED",
						"-j", "ACCEPT",
					})
				}

			}

			if testReject(rule.policy) && testObserveContinue(rule.policy) {
				rulesBucket.RejectObserveContinue = append(rulesBucket.RejectObserveContinue,
					appACLS...)

				if (rule.policy.Action&policy.Accept) != 0 && (proto == constants.UDPProtoNum) {
					// Add a corresponding rule at the top of netChain.
					rulesBucket.RejectObserveContinue = append(rulesBucket.RejectObserveContinue, []string{
						i.appPacketIPTableContext, netChain,
						"-p", proto,
						"-m", "set", "--match-set", rule.ipset, "src",
						"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
						"-m", "state", "--state", "ESTABLISHED",
						"-j", "ACCEPT",
					})
				}
			}

			if testAccept(rule.policy) && testObserveContinue(rule.policy) {
				rulesBucket.AcceptObserveContinue = append(rulesBucket.AcceptObserveContinue,
					appACLS...)

				if (rule.policy.Action&policy.Accept) != 0 && (proto == constants.UDPProtoNum) {
					// Add a corresponding rule at the top of netChain.
					rulesBucket.AcceptObserveContinue = append(rulesBucket.AcceptObserveContinue, []string{
						i.appPacketIPTableContext, netChain,
						"-p", proto,
						"-m", "set", "--match-set", rule.ipset, "src",
						"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
						"-m", "state", "--state", "ESTABLISHED",
						"-j", "ACCEPT",
					})
				}
			}

			if testAccept(rule.policy) && testNotObserved(rule.policy) {
				rulesBucket.AcceptNotObserved = append(rulesBucket.AcceptNotObserved,
					appACLS...)

				if (rule.policy.Action&policy.Accept) != 0 && (proto == constants.UDPProtoNum) {
					// Add a corresponding rule at the top of netChain.
					rulesBucket.AcceptNotObserved = append(rulesBucket.AcceptNotObserved, []string{
						i.appPacketIPTableContext, netChain,
						"-p", proto,
						"-m", "set", "--match-set", rule.ipset, "src",
						"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
						"-m", "state", "--state", "ESTABLISHED",
						"-j", "ACCEPT",
					})
				}
			}

			if testAccept(rule.policy) && testObserveApply(rule.policy) {
				rulesBucket.AcceptObserveApply = append(rulesBucket.AcceptObserveApply,
					appACLS...)

				if (rule.policy.Action&policy.Accept) != 0 && (proto == constants.UDPProtoNum) {
					// Add a corresponding rule at the top of netChain.
					rulesBucket.AcceptObserveApply = append(rulesBucket.AcceptObserveApply, []string{
						i.appPacketIPTableContext, netChain,
						"-p", proto,
						"-m", "set", "--match-set", rule.ipset, "src",
						"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
						"-m", "state", "--state", "ESTABLISHED",
						"-j", "ACCEPT",
					})
				}
			}
		}
	}

}

func (i *Instance) addAllNetACLS(contextID, appChain, netChain string, rules []aclIPset, rulesBucket *rulesInfo) {

	insertOrder := int(1)
	intP := &insertOrder
	var acceptRules []string

	testObserveContinue := func(p *policy.FlowPolicy) bool {
		return p.ObserveAction.ObserveContinue()
	}

	testNotObserved := func(p *policy.FlowPolicy) bool {
		return !p.ObserveAction.Observed()
	}

	testObserveApply := func(p *policy.FlowPolicy) bool {
		return p.ObserveAction.ObserveApply()
	}

	testReject := func(p *policy.FlowPolicy) bool {
		return (p.Action&policy.Reject != 0)
	}

	testAccept := func(p *policy.FlowPolicy) bool {
		return (p.Action&policy.Accept != 0)
	}

	for _, rule := range rules {

		for _, proto := range rule.protocols {

			netACLS := i.getRules(contextID, &rule, intP, netChain, "11", proto, "src", "Append")

			if testReject(rule.policy) && testObserveApply(rule.policy) {

				rulesBucket.RejectObserveApply = append(rulesBucket.RejectObserveApply,
					netACLS...)

				if (rule.policy.Action & policy.Accept) != 0 {

					if proto == constants.TCPProtoNum {
						acceptRules = []string{
							i.appPacketIPTableContext, appChain,
							"-p", proto,
							"-m", "set", "--match-set", rule.ipset, "dst",
							"-m", "set", "!", "--match-set", targetNetworkSet, "dst",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						}
					}

					// not targetNetSet match for udp.
					if proto == constants.UDPProtoNum {
						acceptRules = []string{
							i.appPacketIPTableContext, appChain,
							"-p", proto,
							"-m", "set", "--match-set", rule.ipset, "dst",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						}
					}

					// Add a corresponding rule at the top of appChain for traffic in other direction.
					rulesBucket.RejectObserveApply = append(rulesBucket.RejectObserveApply,
						acceptRules)
				}
			}

			if testReject(rule.policy) && testNotObserved(rule.policy) {
				rulesBucket.RejectNotObserved = append(rulesBucket.RejectNotObserved,
					netACLS...)

				if (rule.policy.Action & policy.Accept) != 0 {
					if proto == constants.TCPProtoNum {
						acceptRules = []string{
							i.appPacketIPTableContext, appChain,
							"-p", proto,
							"-m", "set", "--match-set", rule.ipset, "dst",
							"-m", "set", "!", "--match-set", targetNetworkSet, "dst",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						}
					}

					// not targetNetSet match for udp.
					if proto == constants.UDPProtoNum {
						acceptRules = []string{
							i.appPacketIPTableContext, appChain,
							"-p", proto,
							"-m", "set", "--match-set", rule.ipset, "dst",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						}
					}
					// Add a corresponding rule at the top of appChain.
					rulesBucket.RejectNotObserved = append(rulesBucket.RejectNotObserved,
						acceptRules)

				}
			}

			if testReject(rule.policy) && testObserveContinue(rule.policy) {
				rulesBucket.RejectObserveContinue = append(rulesBucket.RejectObserveContinue,
					netACLS...)

				if (rule.policy.Action & policy.Accept) != 0 {
					if proto == constants.TCPProtoNum {
						acceptRules = []string{
							i.appPacketIPTableContext, appChain,
							"-p", proto,
							"-m", "set", "--match-set", rule.ipset, "dst",
							"-m", "set", "!", "--match-set", targetNetworkSet, "dst",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						}
					}

					// not targetNetSet match for udp.
					if proto == constants.UDPProtoNum {
						acceptRules = []string{
							i.appPacketIPTableContext, appChain,
							"-p", proto,
							"-m", "set", "--match-set", rule.ipset, "dst",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						}
					}
					// Add a corresponding rule at the top of appChain.
					rulesBucket.RejectObserveContinue = append(rulesBucket.RejectObserveContinue,
						acceptRules)

				}

			}

			if testAccept(rule.policy) && testObserveContinue(rule.policy) {

				rulesBucket.AcceptObserveContinue = append(rulesBucket.AcceptObserveContinue,
					netACLS...)

				if (rule.policy.Action & policy.Accept) != 0 {
					if proto == constants.TCPProtoNum {
						acceptRules = []string{
							i.appPacketIPTableContext, appChain,
							"-p", proto,
							"-m", "set", "--match-set", rule.ipset, "dst",
							"-m", "set", "!", "--match-set", targetNetworkSet, "dst",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						}
					}

					// not targetNetSet match for udp.
					if proto == constants.UDPProtoNum {
						acceptRules = []string{
							i.appPacketIPTableContext, appChain,
							"-p", proto,
							"-m", "set", "--match-set", rule.ipset, "dst",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						}
					}
					// Add a corresponding rule at the top of appChain.
					rulesBucket.AcceptObserveContinue = append(rulesBucket.AcceptObserveContinue,
						acceptRules)

				}
			}

			if testAccept(rule.policy) && testNotObserved(rule.policy) {
				rulesBucket.AcceptNotObserved = append(rulesBucket.AcceptNotObserved,
					netACLS...)

				if (rule.policy.Action & policy.Accept) != 0 {

					if proto == constants.TCPProtoNum {
						acceptRules = []string{
							i.appPacketIPTableContext, appChain,
							"-p", proto,
							"-m", "set", "--match-set", rule.ipset, "dst",
							"-m", "set", "!", "--match-set", targetNetworkSet, "dst",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						}
					}

					// not targetNetSet match for udp.
					if proto == constants.UDPProtoNum {
						acceptRules = []string{
							i.appPacketIPTableContext, appChain,
							"-p", proto,
							"-m", "set", "--match-set", rule.ipset, "dst",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						}
					}
					// Add a corresponding rule at the top of appChain.
					rulesBucket.AcceptNotObserved = append(rulesBucket.AcceptNotObserved,
						acceptRules)

				}
			}

			if testAccept(rule.policy) && testObserveApply(rule.policy) {
				rulesBucket.AcceptObserveApply = append(rulesBucket.AcceptObserveApply,
					netACLS...)

				if (rule.policy.Action & policy.Accept) != 0 {
					if proto == constants.TCPProtoNum {
						acceptRules = []string{
							i.appPacketIPTableContext, appChain,
							"-p", proto,
							"-m", "set", "--match-set", rule.ipset, "dst",
							"-m", "set", "!", "--match-set", targetNetworkSet, "dst",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						}
					}

					// not targetNetSet match for udp.
					if proto == constants.UDPProtoNum {
						acceptRules = []string{
							i.appPacketIPTableContext, appChain,
							"-p", proto,
							"-m", "set", "--match-set", rule.ipset, "dst",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						}
					}
					// Add a corresponding rule at the top of appChain.
					rulesBucket.AcceptObserveApply = append(rulesBucket.AcceptObserveApply,
						acceptRules)

				}
			}

		}
	}

}

// addAppACLs adds a set of rules to the external services that are initiated
// by an application. The allow rules are inserted with highest priority.
func (i *Instance) addAppACLs(contextID, appChain, netChain string, rules []aclIPset) error {

	rulesBucket := &rulesInfo{
		RejectObserveApply:    [][]string{},
		RejectNotObserved:     [][]string{},
		RejectObserveContinue: [][]string{},

		AcceptObserveApply:    [][]string{},
		AcceptNotObserved:     [][]string{},
		AcceptObserveContinue: [][]string{},
	}

	i.addAllAppACLS(contextID, appChain, netChain, rules, rulesBucket)

	tmpl := template.Must(template.New(acls).Funcs(template.FuncMap{
		"joinRule": func(rule []string) string {
			zap.L().Info("rules is", zap.Strings("rule", rule))
			return strings.Join(rule, " ")
		},
	}).Parse(acls))

	aclRules, err := extractRulesFromTemplate(tmpl, *rulesBucket)
	if err != nil {
		return fmt.Errorf("unable to extract rules from template: %s", err)
	}

	if err := i.processRulesFromList(aclRules, "Append"); err != nil {
		return fmt.Errorf("unable to install appACL rules:%s", err)
	}

	return nil
}

// addNetACLs adds iptables rules that manage traffic from external services. The
// explicit rules are added with the highest priority since they are direct allows.
func (i *Instance) addNetACLs(contextID, appChain, netChain string, rules []aclIPset) error {

	rulesBucket := &rulesInfo{
		RejectObserveApply:    [][]string{},
		RejectNotObserved:     [][]string{},
		RejectObserveContinue: [][]string{},

		AcceptObserveApply:    [][]string{},
		AcceptNotObserved:     [][]string{},
		AcceptObserveContinue: [][]string{},
	}

	i.addAllNetACLS(contextID, appChain, netChain, rules, rulesBucket)

	tmpl := template.Must(template.New(acls).Funcs(template.FuncMap{
		"joinRule": func(rule []string) string {
			zap.L().Info("rules is", zap.Strings("rule", rule))
			return strings.Join(rule, " ")
		},
	}).Parse(acls))

	aclRules, err := extractRulesFromTemplate(tmpl, *rulesBucket)
	if err != nil {
		return fmt.Errorf("unable to extract rules from template: %s", err)
	}

	if err := i.processRulesFromList(aclRules, "Append"); err != nil {
		return fmt.Errorf("unable to install appACL rules:%s", err)
	}

	return nil
}

// deleteChainRules deletes the rules that send traffic to our chain
func (i *Instance) deleteChainRules(contextID, portSetName, appChain, netChain, tcpPorts, udpPorts string, mark string, uid string, proxyPort string, proxyPortSetName string, puType string) error {

	if i.mode == constants.LocalServer {
		if uid == "" {
			if udpPorts != "0" {
				// Delete the postrouting Nat rule for udp.
				err := i.processRulesFromList(i.getUDPNatRule(udpPorts, false), "Delete")
				if err != nil {
					return fmt.Errorf("Unable to delete nat rule for udp: %s", err)
				}
			}

			// choose correct chains based on puType
			appSection := ""
			netSection := ""
			switch puType {
			case extractors.LinuxPU:
				appSection = TriremeOutput
				netSection = TriremeInput
			case extractors.HostModeNetworkPU:
				appSection = NetworkSvcOutput
				netSection = NetworkSvcInput
			case extractors.HostPU:
				appSection = HostModeOutput
				netSection = HostModeInput
			default:
				appSection = TriremeOutput
				netSection = TriremeInput
			}

			return i.processRulesFromList(i.cgroupChainRules(contextID, appChain, netChain, mark, portSetName, tcpPorts, udpPorts, proxyPort, proxyPortSetName, appSection, netSection, puType), "Delete")
		}

		return i.processRulesFromList(i.uidChainRules(tcpPorts, portSetName, appChain, netChain, mark, uid, proxyPort, proxyPortSetName), "Delete")
	}

	return i.processRulesFromList(i.chainRules(contextID, appChain, netChain, proxyPort, proxyPortSetName), "Delete")
}

// deleteAllContainerChains removes all the container specific chains and basic rules
func (i *Instance) deleteAllContainerChains(appChain, netChain string) error {

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

	aclInfo := ACLInfo{
		MangleTable:           i.appPacketIPTableContext,
		NatTable:              i.appProxyIPTableContext,
		HostInput:             HostModeInput,
		HostOutput:            HostModeOutput,
		NetworkSvcInput:       NetworkSvcInput,
		NetworkSvcOutput:      NetworkSvcOutput,
		TriremeInput:          TriremeInput,
		TriremeOutput:         TriremeOutput,
		UIDInput:              uidInput,
		UIDOutput:             uidchain,
		MangleProxyAppChain:   proxyOutputChain,
		MangleProxyNetChain:   proxyInputChain,
		NatProxyAppChain:      natProxyOutputChain,
		NatProxyNetChain:      natProxyInputChain,
		UDPSignature:          packet.UDPAuthMarker,
		DefaultConnmark:       strconv.Itoa(int(constants.DefaultConnMark)),
		QueueBalanceNetSyn:    i.fqc.GetNetworkQueueSynStr(),
		QueueBalanceNetSynAck: i.fqc.GetNetworkQueueSynAckStr(),
		QueueBalanceAppSyn:    i.fqc.GetApplicationQueueSynStr(),
		QueueBalanceAppSynAck: i.fqc.GetApplicationQueueSynAckStr(),
		TargetNetSet:          targetNetworkSet,
		InitialMarkVal:        strconv.Itoa(cgnetcls.Initialmarkval - 1),
		RawSocketMark:         strconv.Itoa(afinetrawsocket.ApplicationRawSocketMark),
		ProxyMark:             proxyMark,
	}

	tmpl := template.Must(template.New(globalRules).Funcs(template.FuncMap{
		"isLocalServer": func() bool {
			return i.mode == constants.LocalServer
		},
	}).Parse(globalRules))

	rules, err := extractRulesFromTemplate(tmpl, aclInfo)
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
		"-j", natProxyInputChain)
	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at net: %s", err)
	}

	err = i.ipt.Insert(i.appProxyIPTableContext,
		ipTableSectionOutput, 1,
		"-j", natProxyOutputChain)
	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at net: %s", err)
	}

	return nil
}

func (i *Instance) removeNatRules() error {

	aclInfo := ACLInfo{

		NatTable:         i.appProxyIPTableContext,
		NatProxyNetChain: natProxyInputChain,
		NatProxyAppChain: natProxyOutputChain,
	}

	tmpl := template.Must(template.New(deleteNatRules).Funcs(template.FuncMap{
		"isLocalServer": func() bool {
			return i.mode == constants.LocalServer
		},
	}).Parse(deleteNatRules))

	rules, err := extractRulesFromTemplate(tmpl, aclInfo)
	if err != nil {
		return fmt.Errorf("unable to create trireme chains:%s", err)
	}

	i.processRulesFromList(rules, "Delete") // nolint
	return nil
}

func (i *Instance) cleanACLs() error { // nolint

	// First clear the nat rules
	if err := i.removeNatRules(); err != nil {
		zap.L().Error("unable to remove nat proxy rules")
	}

	aclInfo := ACLInfo{
		MangleTable:         i.appPacketIPTableContext,
		NatTable:            i.appProxyIPTableContext,
		HostInput:           HostModeInput,
		HostOutput:          HostModeOutput,
		NetworkSvcInput:     NetworkSvcInput,
		NetworkSvcOutput:    NetworkSvcOutput,
		TriremeInput:        TriremeInput,
		TriremeOutput:       TriremeOutput,
		UIDInput:            uidInput,
		UIDOutput:           uidchain,
		MangleProxyAppChain: proxyOutputChain,
		MangleProxyNetChain: proxyInputChain,
		NatProxyNetChain:    natProxyInputChain,
		NatProxyAppChain:    natProxyOutputChain,
	}

	tmpl := template.Must(template.New(deleteChains).Funcs(template.FuncMap{
		"isLocalServer": func() bool {
			return i.mode == constants.LocalServer
		},
	}).Parse(deleteChains))

	rules, err := extractRulesFromTemplate(tmpl, aclInfo)
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

		// Flush the chains
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

// addExclusionACLs adds the set of IP addresses that must be excluded
func (i *Instance) addExclusionACLs(appChain, netChain string, exclusions []string) error {

	aclInfo := ACLInfo{
		MangleTable: i.appPacketIPTableContext,
		AppChain:    appChain,
		NetChain:    netChain,
		Exclusions:  exclusions,
	}

	tmpl := template.Must(template.New(excludedACLs).Parse(excludedACLs))

	rules, err := extractRulesFromTemplate(tmpl, aclInfo)
	if err != nil {
		return fmt.Errorf("unable to add extract exclusion rules: %s", err)
	}

	return i.processRulesFromList(rules, "Append")

}

func (i *Instance) addNATExclusionACLs(cgroupMark, setName string, exclusions []string) error {
	destSetName, srvSetName := i.getSetNames(setName)

	aclInfo := ACLInfo{
		NatTable:   i.appProxyIPTableContext,
		NetChain:   natProxyInputChain,
		AppChain:   natProxyOutputChain,
		Exclusions: exclusions,
		DestIPSet:  destSetName,
		SrvIPSet:   srvSetName,
		CgroupMark: cgroupMark,
		ProxyMark:  proxyMark,
	}

	tmpl := template.Must(template.New(excludedNatACLs).Funcs(template.FuncMap{
		"isCgroupSet": func() bool {
			return cgroupMark != ""
		},
	}).Parse(excludedNatACLs))

	rules, err := extractRulesFromTemplate(tmpl, aclInfo)
	if err != nil {
		return fmt.Errorf("unable to add extract exclusion rules: %s", err)
	}

	return i.processRulesFromList(rules, "Append")

}

// deleteExclusionACLs adds the set of IP addresses that must be excluded
func (i *Instance) deleteNATExclusionACLs(cgroupMark, setName string, exclusions []string) error {

	destSetName, srvSetName := i.getSetNames(setName)

	aclInfo := ACLInfo{
		NatTable:   i.appProxyIPTableContext,
		NetChain:   natProxyInputChain,
		AppChain:   natProxyOutputChain,
		Exclusions: exclusions,
		DestIPSet:  destSetName,
		SrvIPSet:   srvSetName,
		CgroupMark: cgroupMark,
		ProxyMark:  proxyMark,
	}

	tmpl := template.Must(template.New(excludedNatACLs).Funcs(template.FuncMap{
		"isCgroupSet": func() bool {
			return cgroupMark != ""
		},
	}).Parse(excludedNatACLs))

	rules, err := extractRulesFromTemplate(tmpl, aclInfo)
	if err != nil {
		return fmt.Errorf("unable to add extract exclusion rules: %s", err)
	}

	return i.processRulesFromList(rules, "Delete")
}
