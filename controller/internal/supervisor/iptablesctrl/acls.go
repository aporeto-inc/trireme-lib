package iptablesctrl

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"strconv"
	"strings"

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

func (i *Instance) puChainRules(contextID, appChain string, netChain string, mark string, tcpPortSet, tcpPorts, udpPorts string, proxyPort string, proxyPortSetName string,
	appSection, netSection string) [][]string {

	cgroupChains := CgroupChains{
		Table:       i.appPacketIPTableContext,
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

	buffer := bytes.NewBuffer([]byte{})

	tmpl := template.Must(template.New(cgroupRules).Funcs(template.FuncMap{
		"ifUDPPorts": func() bool {
			return udpPorts != "0"
		},
		"ifTCPPorts": func() bool {
			return tcpPorts != "0"
		},
		"isHostPU": func() bool {
			return appSection == HostModeOutput && netSection == HostModeInput
		},
	}).Parse(cgroupRules))

	if err := tmpl.Execute(buffer, cgroupChains); err != nil {
		zap.L().Warn("Unable to add pu trap rules. We will fail")
	}

	rules := [][]string{}
	for _, m := range strings.Split(buffer.String(), "\n") {
		rule := strings.Split(m, " ")
		zap.L().Info("Rules are", zap.Strings("rule", rule), zap.Reflect("len", len(rule)))
		// ignore empty lines in the buffer
		if len(rule) <= 1 {
			continue
		}
		rules = append(rules, rule)
	}

	return append(rules, i.proxyRules(proxyPort, proxyPortSetName, mark)...)
}

// This refers to the pu chain rules for pus in older distros like RH 6.9/Ubuntu 14.04. The rules
// consider source ports to identify packets from the process.
func (i *Instance) legacyPuChainRules(contextID, appChain string, netChain string, mark string, tcpPorts, udpPorts string, proxyPort string, proxyPortSetName string,
	appSection, netSection string, puType string) [][]string {

	iptableCgroupSection := appSection
	iptableNetSection := netSection
	rules := [][]string{}

	if tcpPorts != "0" {
		rules = append(rules, [][]string{
			{
				i.appPacketIPTableContext,
				iptableCgroupSection,
				"-p", tcpProto,
				"-m", "multiport",
				"--source-ports", tcpPorts,
				"-m", "comment", "--comment", "Server-specific-chain",
				"-j", "MARK", "--set-mark", mark,
			},
			{
				i.appPacketIPTableContext,
				iptableCgroupSection,
				"-p", tcpProto,
				"-m", "multiport",
				"--source-ports", tcpPorts,
				"-m", "comment", "--comment", "Server-specific-chain",
				"-j", appChain,
			},
			{
				i.netPacketIPTableContext,
				iptableNetSection,
				"-p", tcpProto,
				"-m", "multiport",
				"--destination-ports", tcpPorts,
				"-m", "comment", "--comment", "Container-specific-chain",
				"-j", netChain,
			}}...)
	}

	if udpPorts != "0" {
		rules = append(rules, [][]string{
			{
				i.appPacketIPTableContext,
				iptableCgroupSection,
				"-p", udpProto,
				"-m", "multiport",
				"--source-ports", udpPorts,
				"-m", "comment", "--comment", "Server-specific-chain",
				"-j", "MARK", "--set-mark", mark,
			},
			{
				i.appPacketIPTableContext,
				iptableCgroupSection,
				"-p", udpProto, "-m", "mark", "--mark", mark,
				"-m", "addrtype", "--src-type", "LOCAL",
				"-m", "addrtype", "--dst-type", "LOCAL",
				"-m", "state", "--state", "NEW",
				"-j", "NFLOG", "--nflog-group", "10",
				"--nflog-prefix", policy.DefaultAcceptLogPrefix(contextID),
			},
			{
				i.appPacketIPTableContext,
				iptableCgroupSection,
				"-m", "comment", "--comment", "traffic-same-pu",
				"-p", udpProto, "-m", "mark", "--mark", mark,
				"-m", "addrtype", "--src-type", "LOCAL",
				"-m", "addrtype", "--dst-type", "LOCAL",
				"-j", "ACCEPT",
			},
			{
				i.appPacketIPTableContext,
				iptableCgroupSection,
				"-p", udpProto,
				"-m", "multiport",
				"--source-ports", udpPorts,
				"-m", "comment", "--comment", "Server-specific-chain",
				"-j", appChain,
			},
			{
				i.netPacketIPTableContext,
				iptableNetSection,
				"-m", "comment", "--comment", "traffic-same-pu",
				"-p", udpProto, "-m", "mark", "--mark", mark,
				"-m", "addrtype", "--src-type", "LOCAL",
				"-m", "addrtype", "--dst-type", "LOCAL",
				"-j", "ACCEPT",
			},
			{
				i.netPacketIPTableContext,
				iptableNetSection,
				"-p", udpProto,
				"-m", "multiport",
				"--destination-ports", udpPorts,
				"-m", "comment", "--comment", "Container-specific-chain",
				"-j", netChain,
			}}...)
	}

	if puType == extractors.HostPU {
		// Add a capture all traffic rule for host pu. This traps all traffic going out
		// of the box.

		rules = append(rules, []string{
			i.appPacketIPTableContext,
			iptableCgroupSection,
			"-m", "comment", "--comment", "capture all outgoing traffic",
			"-j", appChain,
		})
	}

	return append(rules, i.legacyProxyRules(tcpPorts, proxyPort, proxyPortSetName, mark)...)
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

func (i *Instance) uidChainRules(portSetName, appChain string, netChain string, mark string, uid string) [][]string {

	uidRules := UIDRules{
		Table:      i.appPacketIPTableContext,
		PreRouting: ipTableSectionPreRouting,
		AppChain:   appChain,
		NetChain:   netChain,
		Mark:       mark,
		PortSet:    portSetName,
		UID:        uid,
	}

	buffer := bytes.NewBuffer([]byte{})
	tmpl := template.Must(template.New(uidPuRules).Parse(uidPuRules))

	if err := tmpl.Execute(buffer, uidRules); err != nil {
		zap.L().Warn("Unable to add uid rules. We will fail")
	}

	rules := [][]string{}
	for _, m := range strings.Split(buffer.String(), "\n") {
		rule := strings.Split(m, " ")
		zap.L().Info("Rules are", zap.Strings("rule", rule), zap.Reflect("len", len(rule)))
		// ignore empty lines in the buffer
		if len(rule) <= 1 {
			continue
		}
		rules = append(rules, rule)
	}
	return rules
}

// chainRules provides the list of rules that are used to send traffic to
// a particular chain
func (i *Instance) chainRules(contextID string, appChain string, netChain string, proxyPort string, proxyPortSetName string) [][]string {

	containerRules := ContainerRules{
		Table:       i.appPacketIPTableContext,
		AppSection:  i.appPacketIPTableSection,
		NetSection:  i.netPacketIPTableSection,
		AppChain:    appChain,
		NetChain:    netChain,
		NFLOGPrefix: policy.DefaultAcceptLogPrefix(contextID),
	}

	buffer := bytes.NewBuffer([]byte{})
	tmpl := template.Must(template.New(containerPuRules).Parse(containerPuRules))

	if err := tmpl.Execute(buffer, containerRules); err != nil {
		zap.L().Warn("Unable to add uid rules. We will fail")
	}

	rules := [][]string{}
	for _, m := range strings.Split(buffer.String(), "\n") {
		rule := strings.Split(m, " ")
		zap.L().Info("Rules are", zap.Strings("rule", rule), zap.Reflect("len", len(rule)))
		// ignore empty lines in the buffer
		if len(rule) <= 1 {
			continue
		}
		rules = append(rules, rule)
	}

	return append(rules, i.proxyRules(proxyPort, proxyPortSetName, "")...)
}

// proxyRules creates all the proxy specific rules.
func (i *Instance) proxyRules(proxyPort string, proxyPortSetName string, cgroupMark string) [][]string {
	destSetName, srvSetName := i.getSetNames(proxyPortSetName)

	proxyRules := ProxyRules{
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

	buffer := bytes.NewBuffer([]byte{})
	tmpl := template.Must(template.New(proxyChainRules).Funcs(template.FuncMap{
		"ifCgroupSet": func() bool {
			return cgroupMark != ""
		},
	}).Parse(proxyChainRules))

	if err := tmpl.Execute(buffer, proxyRules); err != nil {
		zap.L().Warn("Unable to add proxy rules. We will fail")
	}

	rules := [][]string{}
	for _, m := range strings.Split(buffer.String(), "\n") {
		rule := strings.Split(m, " ")
		zap.L().Info("Rules are", zap.Strings("rule", rule), zap.Reflect("len", len(rule)))
		// ignore empty lines in the buffer
		if len(rule) <= 1 {
			continue
		}
		rules = append(rules, rule)
	}
	return rules
}

//trapRules provides the packet trap rules to add/delete
func (i *Instance) trapRules(appChain string, netChain string, isHostPU bool) [][]string {

	puChains := PUChains{
		Table:              i.appPacketIPTableContext,
		AppChain:           appChain,
		NetChain:           netChain,
		QueueBalanceNetSyn: i.fqc.GetNetworkQueueSynStr(),
		QueueBalanceNetAck: i.fqc.GetNetworkQueueAckStr(),
		QueueBalanceAppSyn: i.fqc.GetApplicationQueueSynStr(),
		QueueBalanceAppAck: i.fqc.GetApplicationQueueAckStr(),
		TargetNetSet:       targetNetworkSet,
		Numpackets:         numPackets,
		InitialCount:       initialCount,
	}

	buffer := bytes.NewBuffer([]byte{})
	tmpl := template.Must(template.New(trapRules).Funcs(template.FuncMap{
		"needDnsRules": func() bool {
			return i.mode == constants.Sidecar || isHostPU || i.isLegacyKernel
		},
	}).Parse(trapRules))

	if err := tmpl.Execute(buffer, puChains); err != nil {
		zap.L().Warn("Unable to add pu trap rules. We will fail")
	}

	rules := [][]string{}
	for _, m := range strings.Split(buffer.String(), "\n") {
		rule := strings.Split(m, " ")
		zap.L().Info("Rules are", zap.Strings("rule", rule), zap.Reflect("len", len(rule)))
		// ignore empty lines
		if len(rule) <= 1 {
			continue
			//return fmt.Errorf("unable to create new chains, invalid command:%s", m)
		}
		rules = append(rules, rule)
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

		return i.processRulesFromList(i.uidChainRules(portSetName, appChain, netChain, mark, uid), "Append")
	}

	return i.processRulesFromList(i.chainRules(contextID, appChain, netChain, proxyPort, proxyPortSetName), "Append")
}

// addPacketTrap adds the necessary iptables rules to capture control packets to user space
func (i *Instance) addPacketTrap(appChain string, netChain string, isHostPU bool) error {

	return i.processRulesFromList(i.trapRules(appChain, netChain, isHostPU), "Append")

}

func (i *Instance) programRule(contextID string, rule *aclIPset, insertOrder *int, chain string, nfLogGroup, proto, ipMatchDirection, order string) error {
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
		return i.processRulesFromList(iptRules, order)
	}

	return i.processRulesFromList(iptRules, order)
}

type rulePred func(policy *policy.FlowPolicy) bool

func (i *Instance) addTCPAppACLS(contextID, chain string, rules []aclIPset) error {
	insertOrder := int(1)
	intP := &insertOrder

	programACLs := func(actionPredicate rulePred, observePredicate rulePred) error {
		for _, rule := range rules {
			for _, proto := range rule.protocols {
				if proto == constants.TCPProtoNum &&
					actionPredicate(rule.policy) &&
					observePredicate(rule.policy) {
					if err := i.programRule(contextID, &rule, intP, chain, "10", constants.TCPProtoNum, "dst", "Insert"); err != nil {
						return err
					}
				}
			}
		}

		return nil
	}

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

	if err := programACLs(testReject, testObserveApply); err != nil {
		return err
	}

	if err := programACLs(testReject, testNotObserved); err != nil {
		return err
	}

	if err := programACLs(testReject, testObserveContinue); err != nil {
		return err
	}

	if err := programACLs(testAccept, testObserveContinue); err != nil {
		return err
	}

	if err := programACLs(testAccept, testNotObserved); err != nil {
		return err
	}

	if err := programACLs(testAccept, testObserveApply); err != nil {
		return err
	}

	return nil
}

func (i *Instance) addOtherAppACLs(contextID, appChain string, rules []aclIPset) error {

	insertOrder := int(1)
	intP := &insertOrder

	programACLs := func(actionPredicate rulePred, observePredicate rulePred) error {
		for _, rule := range rules {
			for _, proto := range rule.protocols {
				if proto != constants.TCPProtoNum &&
					proto != constants.UDPProtoNum &&
					actionPredicate(rule.policy) &&
					observePredicate(rule.policy) {
					if err := i.programRule(contextID, &rule, intP, appChain, "10", proto, "dst", "Append"); err != nil {
						return err
					}
				}
			}
		}

		return nil
	}

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

	if err := programACLs(testReject, testObserveApply); err != nil {
		return err
	}

	if err := programACLs(testReject, testNotObserved); err != nil {
		return err
	}

	if err := programACLs(testReject, testObserveContinue); err != nil {
		return err
	}

	if err := programACLs(testAccept, testObserveContinue); err != nil {
		return err
	}

	if err := programACLs(testAccept, testNotObserved); err != nil {
		return err
	}

	if err := programACLs(testAccept, testObserveApply); err != nil {
		return err
	}

	return nil
}

func (i *Instance) addUDPAppACLS(contextID, appChain, netChain string, rules []aclIPset) error {
	insertOrder := int(1)
	intP := &insertOrder

	programACLs := func(actionPredicate rulePred, observePredicate rulePred) error {
		for _, rule := range rules {
			for _, proto := range rule.protocols {
				if (proto == constants.UDPProtoNum) &&
					actionPredicate(rule.policy) &&
					observePredicate(rule.policy) {
					if err := i.programRule(contextID, &rule, intP, appChain, "10", constants.UDPProtoNum, "dst", "Insert"); err != nil {
						return err
					}

					if (rule.policy.Action & policy.Accept) != 0 {
						// Add a corresponding rule on the top of the network chain.
						if err := i.ipt.Insert(
							i.netPacketIPTableContext, netChain, 1,
							"-p", udpProto,
							"-m", "set", "--match-set", rule.ipset, "src",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					}
				}
			}
		}
		return nil
	}

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

	if err := programACLs(testReject, testObserveContinue); err != nil {
		return err
	}

	if err := programACLs(testReject, testNotObserved); err != nil {
		return err
	}

	if err := programACLs(testReject, testObserveApply); err != nil {
		return err
	}

	if err := programACLs(testAccept, testObserveContinue); err != nil {
		return err
	}

	if err := programACLs(testAccept, testNotObserved); err != nil {
		return err
	}

	if err := programACLs(testAccept, testObserveApply); err != nil {
		return err
	}

	return nil
}

// addAppACLs adds a set of rules to the external services that are initiated
// by an application. The allow rules are inserted with highest priority.
func (i *Instance) addAppACLs(contextID, appChain, netChain string, rules []aclIPset) error {

	if err := i.addTCPAppACLS(contextID, appChain, rules); err != nil {
		return fmt.Errorf("Unable to add tcp app acls: %s", err)
	}

	if err := i.addUDPAppACLS(contextID, appChain, netChain, rules); err != nil {
		return fmt.Errorf("Unable to add udp app acls: %s", err)
	}

	if err := i.addOtherAppACLs(contextID, appChain, rules); err != nil {
		return fmt.Errorf("Unable to add other app acls: %s", err)
	}

	if err := i.ipt.Append(
		i.appPacketIPTableContext, appChain,
		"-d", "0.0.0.0/0",
		"-p", tcpProto, "-m", "state", "--state", "ESTABLISHED",
		"-j", "ACCEPT"); err != nil {

		return fmt.Errorf("unable to add default tcp acl rule for table %s, appChain %s: %s", i.appPacketIPTableContext, appChain, err)
	}

	// Log everything else
	if err := i.ipt.Append(
		i.appPacketIPTableContext,
		appChain,
		"-d", "0.0.0.0/0",
		"-m", "state", "--state", "NEW",
		"-j", "NFLOG", "--nflog-group", "10",
		"--nflog-prefix", policy.DefaultLogPrefix(contextID),
	); err != nil {
		return fmt.Errorf("unable to add acl log rule for table %s, chain %s: %s", i.appPacketIPTableContext, appChain, err)
	}

	// Drop everything else
	if err := i.ipt.Append(
		i.appPacketIPTableContext, appChain,
		"-d", "0.0.0.0/0",
		"-j", "DROP"); err != nil {

		return fmt.Errorf("unable to add default drop acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, appChain, err)
	}

	return nil
}

// addTCPNetACLS adds iptables rules that manage traffic from external services for TCP.
func (i *Instance) addTCPNetACLS(contextID, appChain, netChain string, rules []aclIPset) error {
	insertOrder := int(1)
	intP := &insertOrder

	programACLs := func(actionPredicate rulePred, observePredicate rulePred) error {
		for _, rule := range rules {
			for _, proto := range rule.protocols {
				if proto == constants.TCPProtoNum &&
					actionPredicate(rule.policy) &&
					observePredicate(rule.policy) {
					if err := i.programRule(contextID, &rule, intP, netChain, "11", constants.TCPProtoNum, "src", "Insert"); err != nil {
						return err
					}

					if (rule.policy.Action & policy.Accept) != 0 {
						// Add a corresponding rule at the top of appChain.
						if err := i.ipt.Insert(
							i.appPacketIPTableContext, appChain, 1,
							"-p", tcpProto,
							"-m", "set", "--match-set", rule.ipset, "dst",
							"-m", "set", "!", "--match-set", targetNetworkSet, "dst",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, appChain %s: %s", i.appPacketIPTableContext, appChain, err)
						}
					}

				}
			}
		}
		return nil
	}

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

	if err := programACLs(testReject, testObserveApply); err != nil {
		return err
	}

	if err := programACLs(testReject, testNotObserved); err != nil {
		return err
	}

	if err := programACLs(testReject, testObserveContinue); err != nil {
		return err
	}

	if err := programACLs(testAccept, testObserveContinue); err != nil {
		return err
	}

	if err := programACLs(testAccept, testNotObserved); err != nil {
		return err
	}

	if err := programACLs(testAccept, testObserveApply); err != nil {
		return err
	}

	return nil
}

func (i *Instance) addUDPNetACLS(contextID, appChain, netChain string, rules []aclIPset) error {
	insertOrder := int(1)
	intP := &insertOrder

	programACLs := func(actionPredicate rulePred, observePredicate rulePred) error {
		for _, rule := range rules {
			for _, proto := range rule.protocols {
				if proto == constants.UDPProtoNum &&
					actionPredicate(rule.policy) &&
					observePredicate(rule.policy) {
					if err := i.programRule(contextID, &rule, intP, netChain, "11", constants.UDPProtoNum, "src", "Insert"); err != nil {
						return err
					}

					if (rule.policy.Action & policy.Accept) != 0 {
						// Add a corresponding rule at the top of appChain.
						if err := i.ipt.Insert(
							i.appPacketIPTableContext, appChain, 1,
							"-p", udpProto,
							"-m", "set", "--match-set", rule.ipset, "src",
							"--match", "multiport", "--sports", strings.Join(rule.ports, ","),
							"-m", "state", "--state", "ESTABLISHED",
							"-j", "ACCEPT",
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, appChain %s: %s", i.appPacketIPTableContext, appChain, err)
						}
					}
				}
			}
		}
		return nil
	}

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

	if err := programACLs(testReject, testObserveContinue); err != nil {
		return err
	}

	if err := programACLs(testReject, testNotObserved); err != nil {
		return err
	}

	if err := programACLs(testReject, testObserveApply); err != nil {
		return err
	}

	if err := programACLs(testAccept, testObserveContinue); err != nil {
		return err
	}

	if err := programACLs(testAccept, testNotObserved); err != nil {
		return err
	}

	if err := programACLs(testAccept, testObserveApply); err != nil {
		return err
	}

	return nil
}

func (i *Instance) addOtherNetACLS(contextID, netChain string, rules []aclIPset) error {
	insertOrder := int(1)
	intP := &insertOrder

	programACLs := func(actionPredicate rulePred, observePredicate rulePred) error {
		for _, rule := range rules {
			for _, proto := range rule.protocols {
				if proto != constants.TCPProtoNum &&
					proto != constants.UDPProtoNum &&
					actionPredicate(rule.policy) &&
					observePredicate(rule.policy) {
					if err := i.programRule(contextID, &rule, intP, netChain, "11", proto, "src", "Append"); err != nil {
						return err
					}
				}
			}
		}

		return nil
	}

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

	if err := programACLs(testReject, testObserveApply); err != nil {
		return err
	}

	if err := programACLs(testReject, testNotObserved); err != nil {
		return err
	}

	if err := programACLs(testReject, testObserveContinue); err != nil {
		return err
	}

	if err := programACLs(testAccept, testObserveContinue); err != nil {
		return err
	}

	if err := programACLs(testAccept, testNotObserved); err != nil {
		return err
	}

	if err := programACLs(testAccept, testObserveApply); err != nil {
		return err
	}

	return nil
}

// addNetACLs adds iptables rules that manage traffic from external services. The
// explicit rules are added with the highest priority since they are direct allows.
func (i *Instance) addNetACLs(contextID, appChain, netChain string, rules []aclIPset) error {

	{
		if err := i.addTCPNetACLS(contextID, appChain, netChain, rules); err != nil {
			return fmt.Errorf("Unable to add tcp net acls: %s", err)
		}

		// Accept established connections
		if err := i.ipt.Append(
			i.netPacketIPTableContext, netChain,
			"-s", "0.0.0.0/0",
			"-p", tcpProto, "-m", "state", "--state", "ESTABLISHED",
			"-j", "ACCEPT",
		); err != nil {
			return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
		}
	}

	if err := i.addUDPNetACLS(contextID, appChain, netChain, rules); err != nil {
		return fmt.Errorf("Unable to add udp net acls: %s", err)
	}

	if err := i.addOtherNetACLS(contextID, netChain, rules); err != nil {
		return fmt.Errorf("Unable to add other net acls: %s", err)
	}

	// Log everything
	if err := i.ipt.Append(
		i.netPacketIPTableContext,
		netChain,
		"-s", "0.0.0.0/0",
		"-m", "state", "--state", "NEW",
		"-j", "NFLOG", "--nflog-group", "11",
		"--nflog-prefix", policy.DefaultLogPrefix(contextID),
	); err != nil {
		return fmt.Errorf("unable to add net log rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
	}

	// Drop everything else
	if err := i.ipt.Append(
		i.netPacketIPTableContext, netChain,
		"-s", "0.0.0.0/0",
		"-j", "DROP",
	); err != nil {

		return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
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

		return i.processRulesFromList(i.uidChainRules(portSetName, appChain, netChain, mark, uid), "Delete")
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
func (i *Instance) setGlobalRules(appChain, netChain string) error {

	globalChains := GlobalChains{
		Table:                 i.appPacketIPTableContext,
		HostInput:             HostModeInput,
		HostOutput:            HostModeOutput,
		NetworkSvcInput:       NetworkSvcInput,
		NetworkSvcOutput:      NetworkSvcOutput,
		TriremeInput:          TriremeInput,
		TriremeOutput:         TriremeOutput,
		ProxyInput:            proxyInputChain,
		ProxyOutput:           proxyOutputChain,
		UIDInput:              uidInput,
		UIDOutput:             uidchain,
		UDPSignature:          packet.UDPAuthMarker,
		DefaultConnmark:       strconv.Itoa(int(constants.DefaultConnMark)),
		QueueBalanceNetSyn:    i.fqc.GetNetworkQueueSynStr(),
		QueueBalanceNetSynAck: i.fqc.GetNetworkQueueSynAckStr(),
		QueueBalanceAppSyn:    i.fqc.GetApplicationQueueSynStr(),
		QueueBalanceAppSynAck: i.fqc.GetApplicationQueueSynAckStr(),
		TargetNetSet:          targetNetworkSet,
		InitialMarkVal:        strconv.Itoa(cgnetcls.Initialmarkval - 1),
		RawSocketMark:         strconv.Itoa(afinetrawsocket.ApplicationRawSocketMark),
	}

	buffer := bytes.NewBuffer([]byte{})
	tmpl := template.Must(template.New(globalRules).Funcs(template.FuncMap{
		"isLocalServer": func() bool {
			return i.mode == constants.LocalServer
		},
	}).Parse(globalRules))

	if err := tmpl.Execute(buffer, globalChains); err != nil {
		return fmt.Errorf("unable to create new chains: %s", err)
	}

	rules := [][]string{}
	for _, m := range strings.Split(buffer.String(), "\n") {
		rule := strings.Split(m, " ")
		zap.L().Info("Rules are", zap.Strings("rule", rule), zap.Reflect("len", len(rule)))
		// ignore empty lines
		if len(rule) <= 1 {
			continue
			//return fmt.Errorf("unable to create new chains, invalid command:%s", m)
		}
		rules = append(rules, rule)
	}

	fmt.Println("Rules to be processsed are", rules)
	if err := i.processRulesFromList(rules, "Append"); err != nil {
		return fmt.Errorf("unable to install global rules:%s", err)
	}

	// iptables nat rule. can also be shifted.
	err := i.ipt.Insert(i.appProxyIPTableContext,
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

	err = i.ipt.Insert(i.appProxyIPTableContext,
		natProxyInputChain, 1,
		"-m", "mark",
		"--mark", proxyMark,
		"-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at net: %s", err)
	}

	err = i.ipt.Insert(i.appProxyIPTableContext,
		natProxyOutputChain, 1,
		"-m", "mark",
		"--mark", proxyMark,
		"-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at net: %s", err)
	}

	err = i.ipt.Insert(i.netPacketIPTableContext,
		proxyInputChain, 1,
		"-m", "mark",
		"--mark", proxyMark,
		"-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at net: %s", err)
	}

	err = i.ipt.Insert(i.netPacketIPTableContext,
		proxyOutputChain, 1,
		"-m", "mark",
		"--mark", proxyMark,
		"-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at net: %s", err)
	}

	return nil
}

// CleanGlobalRules cleans the capture rules for SynAck packets
func (i *Instance) CleanGlobalRules() error {

	if err := i.ipt.Delete(
		i.appPacketIPTableContext,
		i.appPacketIPTableSection,
		"-m", "set", "--match-set", targetNetworkSet, "dst",
		"-p", tcpProto, "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "NFQUEUE", "--queue-bypass", "--queue-balance", i.fqc.GetApplicationQueueAckStr()); err != nil {
		zap.L().Debug("Can not clear the SynAck packet capcture app chain", zap.Error(err))
	}

	if err := i.ipt.Delete(
		i.netPacketIPTableContext,
		i.netPacketIPTableSection,
		"-m", "set", "--match-set", targetNetworkSet, "src",
		"-p", tcpProto, "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "NFQUEUE", "--queue-bypass", "--queue-balance", i.fqc.GetNetworkQueueAckStr()); err != nil {
		zap.L().Debug("Can not clear the SynAck packet capcture net chain", zap.Error(err))
	}

	if err := i.ipt.Delete(
		i.appPacketIPTableContext,
		i.appPacketIPTableSection,
		"-m", "connmark", "--mark", strconv.Itoa(int(constants.DefaultConnMark)),
		"-j", "ACCEPT"); err != nil {
		zap.L().Debug("Can not clear the global app mark rule", zap.Error(err))
		return fmt.Errorf("unable to add default allow for marked packets at app: %s", err)
	}

	if err := i.ipt.Delete(
		i.netPacketIPTableContext,
		i.netPacketIPTableSection,
		"-m", "connmark", "--mark", strconv.Itoa(int(constants.DefaultConnMark)),
		"-j", "ACCEPT"); err != nil {
		zap.L().Debug("Can not clear the global net mark rule", zap.Error(err))
	}

	if err := i.ipset.DestroyAll(); err != nil {
		zap.L().Debug("Failed to clear targetIPset", zap.Error(err))
	}

	return nil
}

// CleanAllSynAckPacketCaptures cleans the capture rules for SynAck packets irrespective of NFQUEUE
func (i *Instance) CleanAllSynAckPacketCaptures() error {

	if err := i.ipt.ClearChain(i.appPacketIPTableContext, i.appSynAckIPTableSection); err != nil {
		zap.L().Debug("Can not clear the SynAck packet capcture app chain", zap.Error(err))
	}

	if err := i.ipt.ClearChain(i.netPacketIPTableContext, i.netPacketIPTableSection); err != nil {
		zap.L().Debug("Can not clear the SynAck packet capcture net chain", zap.Error(err))
	}
	if i.mode == constants.LocalServer {
		//We installed UID CHAINS with synack lets remove it here
		if err := i.ipt.ClearChain(i.appPacketIPTableContext, uidchain); err != nil {
			zap.L().Debug("Cannot clear UID Chain", zap.Error(err))
		}
		if err := i.ipt.DeleteChain(i.appPacketIPTableContext, uidchain); err != nil {
			zap.L().Debug("Cannot delete UID Chain", zap.Error(err))
		}

		if err := i.ipt.ClearChain(i.appPacketIPTableContext, uidInput); err != nil {
			zap.L().Debug("Cannot clear UID Chain", zap.Error(err))
		}
		if err := i.ipt.DeleteChain(i.appPacketIPTableContext, uidInput); err != nil {
			zap.L().Debug("Cannot delete UID Chain", zap.Error(err))
		}
	}
	return nil
}

func (i *Instance) removeMarkRule() error {
	return nil
}

func (i *Instance) removeProxyRules(natproxyTableContext string, proxyTableContext string, inputProxySection string, outputProxySection string, natProxyInputChain, natProxyOutputChain, proxyInputChain, proxyOutputChain string) (err error) { // nolint

	zap.L().Debug("Called remove ProxyRules",
		zap.String("natproxyTableContext", natproxyTableContext),
		zap.String("proxyTableContext", proxyTableContext),
		zap.String("inputProxySection", inputProxySection),
		zap.String("outputProxySection", outputProxySection),
		zap.String("natProxyInputChain", natProxyInputChain),
		zap.String("natProxyOutputChain", natProxyOutputChain),
		zap.String("proxyInputChain", proxyInputChain),
		zap.String("proxyOutputChain", proxyOutputChain),
	)

	if err = i.ipt.Delete(natproxyTableContext, inputProxySection, "-p", "tcp", "-m", "addrtype", "--dst-type", "LOCAL", "-j", natProxyInputChain); err != nil {
		zap.L().Debug("Failed to remove rule on", zap.Error(err), zap.String("TableContext", natproxyTableContext), zap.String("TableSection", inputProxySection), zap.String("Target", natProxyInputChain), zap.Error(err))
	}

	if err = i.ipt.Delete(natproxyTableContext, outputProxySection, "-j", natProxyOutputChain); err != nil {
		zap.L().Debug("Failed to remove rule on", zap.Error(err), zap.String("TableContext", natproxyTableContext), zap.String("TableSection", outputProxySection), zap.String("Target", natProxyOutputChain), zap.Error(err))
	}

	if err = i.ipt.ClearChain(natproxyTableContext, natProxyInputChain); err != nil {
		zap.L().Warn("Failed to clear chain", zap.Error(err), zap.String("TableContext", natproxyTableContext), zap.String("Chain", natProxyInputChain))
	}

	if err = i.ipt.ClearChain(natproxyTableContext, natProxyOutputChain); err != nil {
		zap.L().Warn("Failed to clear chain", zap.Error(err), zap.String("TableContext", natproxyTableContext), zap.String("Chain", natProxyOutputChain))
	}

	if err = i.ipt.DeleteChain(natproxyTableContext, natProxyInputChain); err != nil {
		zap.L().Warn("Failed to delete chain", zap.Error(err), zap.String("TableContext", natproxyTableContext), zap.String("Chain", natProxyInputChain))
	}

	if err = i.ipt.DeleteChain(natproxyTableContext, natProxyOutputChain); err != nil {
		zap.L().Warn("Failed to delete chain", zap.Error(err), zap.String("TableContext", natproxyTableContext), zap.String("Chain", natProxyOutputChain))
	}

	//Nat table is clean
	if err = i.ipt.ClearChain(proxyTableContext, proxyInputChain); err != nil {
		zap.L().Warn("Failed to clear chain", zap.Error(err), zap.String("TableContext", proxyTableContext), zap.String("Chain", proxyInputChain))
	}

	if err = i.ipt.DeleteChain(proxyTableContext, proxyInputChain); err != nil {
		zap.L().Warn("Failed to delete chain", zap.Error(err), zap.String("TableContext", proxyTableContext), zap.String("Chain", proxyInputChain))
	}

	if err = i.ipt.ClearChain(proxyTableContext, proxyOutputChain); err != nil {
		zap.L().Warn("Failed to clear chain", zap.Error(err), zap.String("TableContext", proxyTableContext), zap.String("Chain", proxyOutputChain))
	}

	if err = i.ipt.DeleteChain(proxyTableContext, proxyOutputChain); err != nil {
		zap.L().Warn("Failed to clear chain", zap.Error(err), zap.String("TableContext", proxyTableContext), zap.String("Chain", proxyOutputChain))
	}

	return nil
}

func (i *Instance) cleanACLs() error { // nolint

	// Clean the mark rule
	if err := i.removeMarkRule(); err != nil {
		zap.L().Warn("Can not clear the mark rules", zap.Error(err))
	}

	if i.mode == constants.LocalServer {
		if err := i.CleanAllSynAckPacketCaptures(); err != nil {
			zap.L().Warn("Can not clear the SynAck ACLs", zap.Error(err))
		}

	}

	// Clean Application Rules/Chains
	i.cleanACLSection(i.appPacketIPTableContext, i.netPacketIPTableSection, i.appPacketIPTableSection, ipTableSectionPreRouting, chainPrefix)

	// Cannot clear chains in nat table there are masquerade rules in nat table which we don't want to touch
	if err := i.removeProxyRules(i.appProxyIPTableContext,
		i.appPacketIPTableContext,
		ipTableSectionPreRouting,
		ipTableSectionOutput,
		natProxyInputChain,
		natProxyOutputChain,
		proxyInputChain,
		proxyOutputChain); err != nil {
		zap.L().Error("Unable to remove Proxy Rules", zap.Error(err))
	}

	i.ipt.Commit() // nolint

	// Always return nil here. No reason to block anything if cleans fail.
	return nil
}

// cleanTriremeChains clear the trireme/hostmode chains.
func (i *Instance) cleanTriremeChains(context string) error { // nolint

	// clear Trireme-Input/Trireme-Output/NetworkSvc-Input/NetworkSvc-Output/Hostmode-Input/Hostmode-Output
	if err := i.ipt.ClearChain(context, HostModeOutput); err != nil {
		zap.L().Warn("Can not clear the section in iptables",
			zap.String("context", context),
			zap.String("section", HostModeOutput),
			zap.Error(err),
		)
	}

	if err := i.ipt.DeleteChain(context, HostModeOutput); err != nil {
		zap.L().Warn("Can not delete the section in iptables",
			zap.String("context", context),
			zap.String("section", HostModeOutput),
			zap.Error(err),
		)
	}

	if err := i.ipt.ClearChain(context, HostModeInput); err != nil {
		zap.L().Warn("Can not clear the section in iptables",
			zap.String("context", context),
			zap.String("section", HostModeInput),
			zap.Error(err),
		)
	}

	if err := i.ipt.DeleteChain(context, HostModeInput); err != nil {
		zap.L().Warn("Can not delete the section in iptables",
			zap.String("context", context),
			zap.String("section", HostModeInput),
			zap.Error(err),
		)
	}

	if err := i.ipt.ClearChain(context, NetworkSvcOutput); err != nil {
		zap.L().Warn("Can not clear the section in iptables",
			zap.String("context", context),
			zap.String("section", NetworkSvcOutput),
			zap.Error(err),
		)
	}

	if err := i.ipt.DeleteChain(context, NetworkSvcOutput); err != nil {
		zap.L().Warn("Can not delete the section in iptables",
			zap.String("context", context),
			zap.String("section", NetworkSvcOutput),
			zap.Error(err),
		)
	}

	if err := i.ipt.ClearChain(context, NetworkSvcInput); err != nil {
		zap.L().Warn("Can not clear the section in iptables",
			zap.String("context", context),
			zap.String("section", NetworkSvcInput),
			zap.Error(err),
		)
	}

	if err := i.ipt.DeleteChain(context, NetworkSvcInput); err != nil {
		zap.L().Warn("Can not delete the section in iptables",
			zap.String("context", context),
			zap.String("section", NetworkSvcInput),
			zap.Error(err),
		)
	}

	if err := i.ipt.ClearChain(context, TriremeOutput); err != nil {
		zap.L().Warn("Can not clear the section in iptables",
			zap.String("context", context),
			zap.String("section", TriremeOutput),
			zap.Error(err),
		)
	}

	if err := i.ipt.DeleteChain(context, TriremeOutput); err != nil {
		zap.L().Warn("Can not delete the section in iptables",
			zap.String("context", context),
			zap.String("section", TriremeOutput),
			zap.Error(err),
		)
	}

	if err := i.ipt.ClearChain(context, TriremeInput); err != nil {
		zap.L().Warn("Can not clear the section in iptables",
			zap.String("context", context),
			zap.String("section", TriremeInput),
			zap.Error(err),
		)
	}

	if err := i.ipt.DeleteChain(context, TriremeInput); err != nil {
		zap.L().Warn("Can not delete the section in iptables",
			zap.String("context", context),
			zap.String("section", TriremeInput),
			zap.Error(err),
		)
	}

	return nil
}

func (i *Instance) cleanACLSection(context, netSection, appSection, preroutingSection, chainPrefix string) {

	if err := i.ipt.ClearChain(context, appSection); err != nil {
		zap.L().Warn("Can not clear the section in iptables",
			zap.String("context", context),
			zap.String("section", appSection),
			zap.Error(err),
		)
	}

	if err := i.ipt.ClearChain(context, netSection); err != nil {
		zap.L().Warn("Can not clear the section in iptables",
			zap.String("context", context),
			zap.String("section", netSection),
			zap.Error(err),
		)
	}

	if err := i.ipt.ClearChain(context, preroutingSection); err != nil {
		zap.L().Warn("Can not clear the section in iptables",
			zap.String("context", context),
			zap.String("section", netSection),
			zap.Error(err),
		)
	}

	// cleanup the Trireme/hostmode chains in server
	if i.mode == constants.LocalServer {
		if err := i.cleanTriremeChains(context); err != nil {
			zap.L().Warn("Can not clear the Trireme/Hostmode chaines in iptables",
				zap.Error(err),
			)
		}
	}

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

	for _, e := range exclusions {

		if err := i.ipt.Insert(
			i.appPacketIPTableContext, appChain, 1,
			"-d", e,
			"-j", "ACCEPT",
		); err != nil {
			return fmt.Errorf("unable to add exclusion rule for table %s, chain %s, ip %s: %s", i.appPacketIPTableContext, appChain, e, err)
		}

		if err := i.ipt.Insert(
			i.netPacketIPTableContext, netChain, 1,
			"-s", e,
			"-j", "ACCEPT",
		); err != nil {
			return fmt.Errorf("unable to add exclusion rule for table %s, chain %s, ip %s: %s", i.netPacketIPTableContext, netChain, e, err)
		}
	}

	return nil
}

func (i *Instance) addNATExclusionACLs(cgroupMark, setName string, exclusions []string) error {
	destSetName, srvSetName := i.getSetNames(setName)
	for _, e := range exclusions {

		if err := i.ipt.Insert(
			i.appProxyIPTableContext, natProxyInputChain, 1,
			"-p", tcpProto,
			"-m", "set",
			"-s", e,
			"--match-set", srvSetName, "dst",
			"-m", "mark", "!",
			"--mark", proxyMark,
			"-j", "ACCEPT",
		); err != nil {
			return fmt.Errorf("unable to add exclusion NAT ACL for table %s chain %s", i.appProxyIPTableContext, natProxyInputChain)
		}

		if cgroupMark == "" {
			if err := i.ipt.Insert(
				i.appProxyIPTableContext, natProxyOutputChain, 1,
				"-p", tcpProto,
				"-m", "set", "--match-set", destSetName, "dst,dst",
				"-m", "mark", "!", "--mark", proxyMark,
				"-s", e,
				"-j", "ACCEPT",
			); err != nil {
				return fmt.Errorf("unable to add exclusion rule for table %s , chain %s", i.appProxyIPTableContext, natProxyOutputChain)
			}
		} else {
			if err := i.ipt.Insert(
				i.appProxyIPTableContext, natProxyOutputChain, 1,
				"-p", tcpProto,
				"-m", "set", "--match-set", destSetName, "dst,dst",
				"-m", "mark", "!", "--mark", proxyMark,
				"-m", "cgroup", "--cgroup", cgroupMark,
				"-s", e,
				"-j", "ACCEPT",
			); err != nil {
				return fmt.Errorf("unable to add exclusion rule for table %s , chain %s", i.appProxyIPTableContext, natProxyOutputChain)
			}
		}
	}

	return nil
}

// addExclusionACLs adds the set of IP addresses that must be excluded
func (i *Instance) deleteNATExclusionACLs(cgroupMark, setName string, exclusions []string) error {

	destSetName, srvSetName := i.getSetNames(setName)
	for _, e := range exclusions {
		if err := i.ipt.Delete(
			i.appProxyIPTableContext, natProxyInputChain,
			"-p", tcpProto,
			"-m", "set",
			"-s", e,
			"--match-set", srvSetName, "dst",
			"-m", "mark", "!",
			"--mark", proxyMark,
			"-j", "ACCEPT",
		); err != nil {
			return fmt.Errorf("unable to add exclusion NAT ACL for table %s chain %s: %s", i.appProxyIPTableContext, natProxyInputChain, err)
		}
		if cgroupMark == "" {
			if err := i.ipt.Delete(
				i.appProxyIPTableContext, natProxyOutputChain,
				"-p", tcpProto,
				"-m", "set", "--match-set", destSetName, "dst,dst",
				"-m", "mark", "!", "--mark", proxyMark,
				"-s", e,
				"-j", "ACCEPT",
			); err != nil {
				return fmt.Errorf("unable to add exclusion rule for table %s , chain %s: %s", i.appProxyIPTableContext, natProxyOutputChain, err)
			}
		} else {
			if err := i.ipt.Delete(
				i.appProxyIPTableContext, natProxyOutputChain,
				"-p", tcpProto,
				"-m", "set", "--match-set", destSetName, "dst,dst",
				"-m", "mark", "!", "--mark", proxyMark,
				"-m", "cgroup", "--cgroup", cgroupMark,
				"-s", e,
				"-j", "ACCEPT",
			); err != nil {
				return fmt.Errorf("unable to add exclusion rule for table %s , chain %s: %s", i.appProxyIPTableContext, natProxyOutputChain, err)
			}
		}
	}

	return nil
}
