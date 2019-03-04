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

func (i *Instance) uidChainRules(portSetName, appChain string, netChain string, mark string, uid string) [][]string {

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
	return rules
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
		"ifCgroupSet": func() bool {
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
func (i *Instance) trapRules(appChain string, netChain string, isHostPU bool) [][]string {

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

	aclInfo := ACLInfo{
		MangleTable:           i.appPacketIPTableContext,
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

	// iptables nat rule. can also be shifted.
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

func (i *Instance) removeNatRules() error {

	aclInfo := ACLInfo{

		NatTable:         i.appProxyIPTableContext,
		NatProxyNetChain: natProxyInputChain,
		NatProxyAppChain: natProxyOutputChain,
	}

	tmpl := template.Must(template.New(DeleteNatRules).Funcs(template.FuncMap{
		"isLocalServer": func() bool {
			return i.mode == constants.LocalServer
		},
	}).Parse(DeleteNatRules))

	rules, err := extractRulesFromTemplate(tmpl, aclInfo)
	if err != nil {
		return fmt.Errorf("unable to create trireme chains:%s", err)
	}

	zap.L().Info("Deleting nat rules", zap.Reflect("rules", rules))
	i.processRulesFromList(rules, "Delete")
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

	tmpl := template.Must(template.New(DeleteChains).Funcs(template.FuncMap{
		"isLocalServer": func() bool {
			return i.mode == constants.LocalServer
		},
	}).Parse(DeleteChains))

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
			zap.L().Info("clearing chains as of", zap.String("rule", rule))
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
