package iptablesctrl

import (
	"errors"
	"fmt"
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
	observeMark = "39"
	tcpProto    = "tcp"
	udpProto    = "udp"
)

func (i *Instance) cgroupChainRules(appChain string, netChain string, mark string, tcpPortSet, tcpPorts, udpPorts string, proxyPort string, proxyPortSetName string, appSection, netSection string) [][]string {

	iptableCgroupSection := appSection
	iptableNetSection := netSection
	rules := [][]string{
		{
			i.appPacketIPTableContext,
			iptableCgroupSection,
			"-m", "cgroup", "--cgroup", mark,
			"-m", "comment", "--comment", "Server-specific-chain",
			"-j", "MARK", "--set-mark", mark,
		},
		{
			i.appPacketIPTableContext,
			iptableCgroupSection,
			"-m", "cgroup", "--cgroup", mark,
			"-m", "comment", "--comment", "Server-specific-chain",
			"-j", appChain,
		},
	}

	if tcpPorts != "0" {
		rules = append(rules, []string{
			i.netPacketIPTableContext,
			iptableNetSection,
			"-p", "tcp",
			"-m", "multiport",
			"--destination-ports", tcpPorts,
			"-m", "comment", "--comment", "Container-specific-chain",
			"-j", netChain,
		})
	} else {
		rules = append(rules, []string{
			i.netPacketIPTableContext,
			i.netPacketIPTableSection,
			"-p", "tcp",
			"-m", "set", "--match-set", tcpPortSet, "dst",
			"-m", "comment", "--comment", "Container-specific-chain",
			"-j", netChain,
		})
	}

	if udpPorts != "0" {
		rules = append(rules, []string{
			i.netPacketIPTableContext,
			iptableNetSection,
			"-p", "udp",
			"-m", "multiport",
			"--destination-ports", udpPorts,
			"-m", "comment", "--comment", "Container-specific-chain",
			"-j", netChain,
		})
	}
	return append(rules, i.proxyRules(appChain, netChain, tcpPorts, proxyPort, proxyPortSetName, mark)...)
}

func (i *Instance) uidChainRules(portSetName, appChain string, netChain string, mark string, uid string) [][]string {

	str := [][]string{
		{
			i.appPacketIPTableContext,
			uidchain,
			"-m", "owner", "--uid-owner", uid, "-j", "MARK", "--set-mark", mark,
		},
		{
			i.appPacketIPTableContext,
			uidchain,
			"-m", "mark", "--mark", mark,
			"-m", "comment", "--comment", "Server-specific-chain",
			"-j", appChain,
		},
		{
			i.appPacketIPTableContext,
			ipTableSectionPreRouting,
			"-m", "set", "--match-set", portSetName, "dst",
			"-j", "MARK", "--set-mark", mark,
		},
		{
			i.netPacketIPTableContext,
			uidInput,
			"-p", "tcp",
			"-m", "mark",
			"--mark", mark,
			"-m", "comment", "--comment", "Container-specific-chain",
			"-j", netChain,
		},
	}

	return str
}

// chainRules provides the list of rules that are used to send traffic to
// a particular chain
func (i *Instance) chainRules(appChain string, netChain string, port string, proxyPort string, proxyPortSetName string) [][]string {
	rules := [][]string{
		{
			i.appPacketIPTableContext,
			i.appPacketIPTableSection,
			"-m", "comment", "--comment", "Container-specific-chain",
			"-j", appChain,
		},
		{
			i.netPacketIPTableContext,
			i.netPacketIPTableSection,
			"-m", "comment", "--comment", "Container-specific-chain",
			"-j", netChain,
		},
	}

	return append(rules, i.proxyRules(appChain, netChain, port, proxyPort, proxyPortSetName, "")...)
}

// proxyRules creates all the proxy specific rules.
func (i *Instance) proxyRules(appChain string, netChain string, port string, proxyPort string, proxyPortSetName string, cgroupMark string) [][]string {
	destSetName, srvSetName := i.getSetNames(proxyPortSetName)
	proxyrules := [][]string{
		{
			i.appProxyIPTableContext,
			natProxyInputChain,
			"-p", "tcp",
			"-m", "set",
			"--match-set", srvSetName, "dst",
			"-m", "mark", "!",
			"--mark", proxyMark,
			"-j", "REDIRECT",
			"--to-port", proxyPort,
		},
		{
			i.netPacketIPTableContext,
			proxyInputChain,
			"-p", "tcp",
			"-m", "set",
			"--match-set", destSetName, "src,src",
			"-j", "ACCEPT",
		},
		{ // Needed for Web sockets
			i.netPacketIPTableContext,
			proxyInputChain,
			"-p", "tcp",
			"-m", "set",
			"--match-set", srvSetName, "dst",
			"-j", "ACCEPT",
		},
		{ // APIServices
			i.netPacketIPTableContext,
			proxyInputChain,
			"-p", "tcp",
			"-m", "set",
			"--match-set", srvSetName, "src",
			"-j", "ACCEPT",
		},
		{ // APIServices
			i.appPacketIPTableContext,
			proxyInputChain,
			"-p", "tcp",
			"--destination-port", proxyPort,
			"-j", "ACCEPT",
		},
		{ // APIServices
			i.appPacketIPTableContext,
			proxyOutputChain,
			"-p", "tcp",
			"--source-port", proxyPort,
			"-j", "ACCEPT",
		},
		{ // APIServices
			i.appPacketIPTableContext,
			proxyOutputChain,
			"-p", "tcp",
			"-m", "set",
			"--match-set", srvSetName, "src",
			"-j", "ACCEPT",
		},
		{ // Needed for websocket support
			i.appPacketIPTableContext,
			proxyOutputChain,
			"-p", "tcp",
			"-m", "set",
			"--match-set", srvSetName, "dst",
			"-j", "ACCEPT",
		},
		{
			i.appPacketIPTableContext,
			proxyOutputChain,
			"-p", "tcp",
			"-m", "set",
			"--match-set", destSetName, "dst,dst",
			"-m", "mark", "!",
			"--mark", proxyMark,
			"-j", "ACCEPT",
		},
	}

	if cgroupMark == "" {
		proxyrules = append(proxyrules, []string{
			i.appProxyIPTableContext,
			natProxyOutputChain,
			"-p", "tcp",
			"-m", "set", "--match-set", destSetName, "dst,dst",
			"-m", "mark", "!", "--mark", proxyMark,
			"-j", "REDIRECT",
			"--to-port", proxyPort,
		})
	} else {
		proxyrules = append(proxyrules, []string{
			i.appProxyIPTableContext,
			natProxyOutputChain,
			"-p", "tcp",
			"-m", "set", "--match-set", destSetName, "dst,dst",
			"-m", "mark", "!", "--mark", proxyMark,
			"-m", "cgroup", "--cgroup", cgroupMark,
			"-j", "REDIRECT",
			"--to-port", proxyPort,
		})
	}

	return proxyrules
}

//trapRules provides the packet trap rules to add/delete
func (i *Instance) trapRules(appChain string, netChain string, isHostPU bool) [][]string {

	rules := [][]string{}

	// If enforcer is in sidecar mode or host pu mode, we need to add an exclusive dns rule
	// to accept the dns traffic. This is required for the enforcer to talk to
	// to the backend services.
	if i.mode == constants.Sidecar || isHostPU {
		rules = append(rules, []string{
			i.appPacketIPTableContext, appChain,
			"-p", "udp", "--dport", "53",
			"-j", "ACCEPT",
		})
	}

	// Application Packets - SYN
	rules = append(rules, []string{
		i.appPacketIPTableContext, appChain,
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN",
		"-j", "NFQUEUE", "--queue-balance", i.fqc.GetApplicationQueueSynStr(),
	})

	// Application Packets - Evertyhing but SYN and SYN,ACK (first 4 packets). SYN,ACK is captured by global rule
	rules = append(rules, []string{
		i.appPacketIPTableContext, appChain,
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
		"-j", "NFQUEUE", "--queue-balance", i.fqc.GetApplicationQueueAckStr(),
	})

	rules = append(rules, []string{
		i.appPacketIPTableContext, appChain,
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "NFQUEUE", "--queue-balance", i.fqc.GetApplicationQueueAckStr(),
	})

	rules = append(rules, []string{
		i.appPacketIPTableContext, appChain,
		"-m", "set", "--match-set", targetNetworkSet, "dst",
		"-p", "udp",
		"-j", "NFQUEUE", "--queue-balance", i.fqc.GetApplicationQueueAckStr(),
	})

	// If enforcer is in sidecar mode. we need to add an exclusive dns rule
	// to accept the dns traffic. This is required for the enforcer to talk to
	// to the backend services.
	if i.mode == constants.Sidecar || isHostPU {
		rules = append(rules, []string{
			i.netPacketIPTableContext, netChain,
			"-p", "udp", "--sport", "53",
			"-j", "ACCEPT",
		})
	}

	// Network Packets - SYN
	rules = append(rules, []string{
		i.netPacketIPTableContext, netChain,
		"-m", "set", "--match-set", targetNetworkSet, "src",
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN",
		"-j", "NFQUEUE", "--queue-balance", i.fqc.GetNetworkQueueSynStr(),
	})
	// Network Packets - Evertyhing but SYN and SYN,ACK (first 4 packets). SYN,ACK is captured by global rule
	rules = append(rules, []string{
		i.netPacketIPTableContext, netChain,
		"-m", "set", "--match-set", targetNetworkSet, "src",
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
		"-j", "NFQUEUE", "--queue-balance", i.fqc.GetNetworkQueueAckStr(),
	})

	rules = append(rules, []string{
		i.netPacketIPTableContext, netChain,
		"-m", "set", "--match-set", targetNetworkSet, "src",
		"-p", "udp",
		"-j", "NFQUEUE", "--queue-balance", i.fqc.GetNetworkQueueAckStr(),
	})

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
				if err = i.ipt.Insert(cr[0], cr[1], 1, cr[2:]...); err == nil {
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
func (i *Instance) getUDPNatRule(udpPorts string) [][]string {

	rules := [][]string{
		{
			"nat",
			"POSTROUTING",
			"-p", "udp",
			"-m", "addrtype", "--src-type", "LOCAL",
			"-m", "multiport",
			"--source-ports", udpPorts,
			"-j", "ACCEPT",
		},
	}
	return rules
}

// addChainrules implements all the iptable rules that redirect traffic to a chain
func (i *Instance) addChainRules(portSetName string, appChain string, netChain string, tcpPorts, udpPorts string, mark string, uid string, proxyPort string, proxyPortSetName string, puType string) error {
	if i.mode == constants.LocalServer {
		if uid == "" {
			if udpPorts != "0" {
				// Add a postrouting Nat rule for udp to not masquarade udp traffic for host servers.
				err := i.processRulesFromList(i.getUDPNatRule(udpPorts), "Insert")
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

			return i.processRulesFromList(i.cgroupChainRules(appChain, netChain, mark, portSetName, tcpPorts, udpPorts, proxyPort, proxyPortSetName, appSection, netSection), "Append")
		}

		return i.processRulesFromList(i.uidChainRules(portSetName, appChain, netChain, mark, uid), "Append")
	}

	return i.processRulesFromList(i.chainRules(appChain, netChain, tcpPorts, proxyPort, proxyPortSetName), "Append")
}

// addPacketTrap adds the necessary iptables rules to capture control packets to user space
func (i *Instance) addPacketTrap(appChain string, netChain string, networks []string, isHostPU bool) error {

	return i.processRulesFromList(i.trapRules(appChain, netChain, isHostPU), "Append")

}

func (i *Instance) addTCPAppACLS(contextID, chain string, rules policy.IPRuleList) error {

	for loop := 0; loop < 3; loop++ {

		for _, rule := range rules {

			observeContinue := rule.Policy.ObserveAction.ObserveContinue()
			switch loop {
			case 0:
				if !observeContinue {
					continue
				}
			case 1:
				if rule.Policy.ObserveAction.Observed() {
					continue
				}
			case 2:
				if !rule.Policy.ObserveAction.ObserveApply() {
					continue
				}
			}

			proto := strings.ToLower(rule.Protocol)

			if proto == "tcp" {

				switch rule.Policy.Action & (policy.Accept | policy.Reject) {
				case policy.Accept:

					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Append(
							i.appPacketIPTableContext,
							chain,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-m", "state", "--state", "NEW",
							"-j", "NFLOG", "--nflog-group", "10",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add acl log rule for table %s, appChain %s: %s", i.appPacketIPTableContext, chain, err)
						}
					}

					if observeContinue {
						if err := i.ipt.Append(
							i.appPacketIPTableContext, chain,
							"-p", rule.Protocol, "-m", "state", "--state", "NEW",
							"-d", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, chain, err)
						}
					} else {
						if err := i.ipt.Append(
							i.appPacketIPTableContext, chain,
							"-p", rule.Protocol, "-m", "state", "--state", "NEW",
							"-d", rule.Address,
							"--dport", rule.Port,
							"-j", "ACCEPT",
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, chain, err)
						}
					}

				case policy.Reject:
					if observeContinue {
						if err := i.ipt.Insert(
							i.appPacketIPTableContext, chain, 1,
							"-p", rule.Protocol, "-m", "state", "--state", "NEW",
							"-d", rule.Address,
							"--dport", rule.Port,
							"-m", "set", "!", "--match-set", targetNetworkSet, "dst",
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, chain, err)
						}
					} else {
						if err := i.ipt.Insert(
							i.appPacketIPTableContext, chain, 1,
							"-p", rule.Protocol, "-m", "state", "--state", "NEW",
							"-d", rule.Address,
							"--dport", rule.Port,
							"-m", "set", "!", "--match-set", targetNetworkSet, "dst",
							"-j", "DROP",
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, chain, err)
						}
					}

					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Insert(
							i.appPacketIPTableContext,
							chain,
							1,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"--dport", rule.Port,
							"-m", "set", "!", "--match-set", targetNetworkSet, "dst",
							"-m", "mark", "!", "--mark", observeMark,
							"-m", "state", "--state", "NEW",
							"-j", "NFLOG", "--nflog-group", "10",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add acl log rule for table %s, chain %s: %s", i.appPacketIPTableContext, chain, err)
						}
					}

				default:
					continue
				}

			}
		}
	}

	return nil
}

func (i *Instance) addOtherAppACLs(contextID, appChain string, rules policy.IPRuleList) error {

	for loop := 0; loop < 3; loop++ {

		for _, rule := range rules {

			observeContinue := rule.Policy.ObserveAction.ObserveContinue()
			switch loop {
			case 0:
				if !observeContinue {
					continue
				}
			case 1:
				if rule.Policy.ObserveAction.Observed() {
					continue
				}
			case 2:
				if !rule.Policy.ObserveAction.ObserveApply() {
					continue
				}
			}

			proto := strings.ToLower(rule.Protocol)
			if proto != udpProto && proto != tcpProto {

				switch rule.Policy.Action & (policy.Accept | policy.Reject) {
				case policy.Accept:

					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Append(
							i.appPacketIPTableContext,
							appChain,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"-m", "state", "--state", "NEW",
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "NFLOG", "--nflog-group", "10",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add acl log rule for table %s, chain %s: %s", i.appPacketIPTableContext, appChain, err)
						}
					}

					if observeContinue {
						if err := i.ipt.Append(
							i.appPacketIPTableContext, appChain,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, appChain, err)
						}
					} else {
						if err := i.ipt.Append(
							i.appPacketIPTableContext, appChain,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"-j", "ACCEPT",
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, appChain, err)
						}
					}

				case policy.Reject:
					if observeContinue {
						if err := i.ipt.Insert(
							i.appPacketIPTableContext, appChain, 1,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, appChain, err)
						}
					} else {
						if err := i.ipt.Insert(
							i.appPacketIPTableContext, appChain, 1,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"-j", "DROP",
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, appChain, err)
						}
					}

					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Insert(
							i.appPacketIPTableContext,
							appChain,
							1,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"-m", "state", "--state", "NEW",
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "NFLOG", "--nflog-group", "10",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add acl log rule for table %s, chain %s: %s", i.appPacketIPTableContext, appChain, err)
						}
					}
				default:
					continue
				}
			}
		}
	}
	return nil
}

func (i *Instance) addUDPAppACLS(contextID, appChain, netChain string, rules policy.IPRuleList) error {

	for loop := 0; loop < 6; loop++ {

		for _, rule := range rules {
			if (loop < 3 && rule.Policy.Action&policy.Reject > 0) || (loop >= 3 && rule.Policy.Action&policy.Accept > 0) {
				// In the first three loops only deal with accept rules.
				// The drop rules are inserted on top.
				continue
			}

			observeContinue := rule.Policy.ObserveAction.ObserveContinue()
			switch loop % 3 {
			case 2:
				if !observeContinue {
					continue
				}
			case 1:
				if rule.Policy.ObserveAction.Observed() {
					continue
				}
			case 0:
				if !rule.Policy.ObserveAction.ObserveApply() {
					continue
				}
			}

			proto := strings.ToLower(rule.Protocol)
			// tcp external services are auto discovered. No need for explicit rules.
			if proto == udpProto {

				switch rule.Policy.Action & (policy.Accept | policy.Reject) {
				case policy.Accept:
					if observeContinue {
						if err := i.ipt.Insert(
							i.appPacketIPTableContext, appChain, 1,
							"-p", rule.Protocol, "-m", "state", "--state", "NEW",
							"-d", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, appChain, err)
						}
					} else {
						if err := i.ipt.Insert(
							i.appPacketIPTableContext, appChain, 1,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"--dport", rule.Port,
							"-j", "ACCEPT",
						); err != nil {
							return fmt.Errorf("unable to add outgoin acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, appChain, err)
						}
					}

					if rule.Policy.Action&policy.Log > 0 {
						if err := i.ipt.Insert(
							i.appPacketIPTableContext,
							appChain, 1,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-m", "state", "--state", "NEW",
							"-j", "NFLOG", "--nflog-group", "10",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add acl log rule for table %s, chain %s: %s", i.appPacketIPTableContext, appChain, err)
						}
					}

					// Add a corresponding rule on the top of the network chain.
					if err := i.ipt.Insert(
						i.netPacketIPTableContext, netChain, 1,
						"-p", rule.Protocol,
						"-s", rule.Address,
						"--sport", rule.Port,
						"-m", "state", "--state", "ESTABLISHED",
						"-j", "ACCEPT",
					); err != nil {
						return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.netPacketIPTableContext, netChain, err)
					}

				case policy.Reject:
					if observeContinue {
						if err := i.ipt.Insert(
							i.appPacketIPTableContext, appChain, 1,
							"-p", rule.Protocol, "-m", "state", "--state", "NEW",
							"-d", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, appChain, err)
						}
					} else {
						if err := i.ipt.Insert(
							i.appPacketIPTableContext, appChain, 1,
							"-p", rule.Protocol, "-m", "state", "--state", "NEW",
							"-d", rule.Address,
							"--dport", rule.Port,
							"-j", "DROP",
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, appChain, err)
						}
					}

					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Insert(
							i.appPacketIPTableContext,
							appChain,
							1,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-m", "state", "--state", "NEW",
							"-j", "NFLOG", "--nflog-group", "10",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add acl log rule for table %s, chain %s: %s", i.appPacketIPTableContext, appChain, err)
						}
					}

				default:
					continue
				}

			}
		}
	}
	return nil
}

// addAppACLs adds a set of rules to the external services that are initiated
// by an application. The allow rules are inserted with highest priority.
func (i *Instance) addAppACLs(contextID, appChain, netChain string, rules policy.IPRuleList) error {

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
		"-p", "tcp", "-m", "state", "--state", "ESTABLISHED",
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
func (i *Instance) addTCPNetACLS(contextID, netChain string, rules policy.IPRuleList) error {

	for loop := 0; loop < 3; loop++ {

		for _, rule := range rules {

			observeContinue := rule.Policy.ObserveAction.ObserveContinue()
			switch loop {
			case 0:
				if !observeContinue {
					continue
				}
			case 1:
				if rule.Policy.ObserveAction.Observed() {
					continue
				}
			case 2:
				if !rule.Policy.ObserveAction.ObserveApply() {
					continue
				}
			}

			proto := strings.ToLower(rule.Protocol)

			if proto == tcpProto {

				switch rule.Policy.Action & (policy.Accept | policy.Reject) {
				case policy.Accept:

					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Append(
							i.netPacketIPTableContext,
							netChain,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-m", "state", "--state", "NEW",
							"-j", "NFLOG", "--nflog-group", "11",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add net log rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					}

					if observeContinue {
						if err := i.ipt.Append(
							i.netPacketIPTableContext, netChain,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					} else {
						if err := i.ipt.Append(
							i.netPacketIPTableContext, netChain,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-j", "ACCEPT",
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					}

				case policy.Reject:
					if observeContinue {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext, netChain, 1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-m", "set", "!", "--match-set", targetNetworkSet, "src",
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					} else {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext, netChain, 1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-m", "set", "!", "--match-set", targetNetworkSet, "src",
							"-j", "DROP",
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					}

					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext,
							netChain,
							1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-m", "set", "!", "--match-set", targetNetworkSet, "src",
							"-m", "mark", "!", "--mark", observeMark,
							"-m", "state", "--state", "NEW",
							"-j", "NFLOG", "--nflog-group", "11",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add net log rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					}

				default:
					continue
				}
			}
		}
	}

	// Accept established connections
	if err := i.ipt.Append(
		i.netPacketIPTableContext, netChain,
		"-s", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "ESTABLISHED",
		"-j", "ACCEPT",
	); err != nil {
		return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
	}

	return nil
}

func (i *Instance) addUDPNetACLS(contextID, appChain, netChain string, rules policy.IPRuleList) error {

	for loop := 0; loop < 6; loop++ {
		for _, rule := range rules {

			if (loop < 3 && rule.Policy.Action&policy.Reject > 0) || (loop >= 3 && rule.Policy.Action&policy.Accept > 0) {
				// In the first three loops only deal with accept rules.
				// The drop rules are inserted on top.
				continue
			}
			observeContinue := rule.Policy.ObserveAction.ObserveContinue()
			switch loop % 3 {
			case 2:
				if !observeContinue {
					continue
				}
			case 1:
				if rule.Policy.ObserveAction.Observed() {
					continue
				}
			case 0:
				if !rule.Policy.ObserveAction.ObserveApply() {
					continue
				}
			}

			proto := strings.ToLower(rule.Protocol)

			if proto == udpProto {

				switch rule.Policy.Action & (policy.Accept | policy.Reject) {
				case policy.Accept:
					if observeContinue {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext, netChain, 1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					} else {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext, netChain, 1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-j", "ACCEPT",
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					}

					if rule.Policy.Action&policy.Log > 0 {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext,
							netChain,
							1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-m", "state", "--state", "NEW",
							"-j", "NFLOG", "--nflog-group", "11",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add net log rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					}

					// Add a corresponding rule at the top of appChain.
					if err := i.ipt.Insert(
						i.appPacketIPTableContext, appChain, 1,
						"-p", rule.Protocol,
						"-d", rule.Address,
						"--sport", rule.Port,
						"-m", "state", "--state", "ESTABLISHED",
						"-j", "ACCEPT",
					); err != nil {
						return fmt.Errorf("unable to add net acl rule for table %s, appChain %s: %s", i.appPacketIPTableContext, appChain, err)
					}

				case policy.Reject:
					if observeContinue {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext, netChain, 1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					} else {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext, netChain, 1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-j", "DROP",
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					}

					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext,
							netChain,
							1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-m", "state", "--state", "NEW",
							"-j", "NFLOG", "--nflog-group", "11",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add net log rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					}

				default:
					continue
				}

			}
		}
	}

	return nil
}

func (i *Instance) addOtherNetACLS(contextID, netChain string, rules policy.IPRuleList) error {

	for loop := 0; loop < 3; loop++ {

		for _, rule := range rules {

			observeContinue := rule.Policy.ObserveAction.ObserveContinue()
			switch loop {
			case 0:
				if !observeContinue {
					continue
				}
			case 1:
				if rule.Policy.ObserveAction.Observed() {
					continue
				}
			case 2:
				if !rule.Policy.ObserveAction.ObserveApply() {
					continue
				}
			}

			proto := strings.ToLower(rule.Protocol)

			if proto != udpProto && proto != tcpProto {

				switch rule.Policy.Action & (policy.Accept | policy.Reject) {
				case policy.Accept:
					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Append(
							i.netPacketIPTableContext,
							netChain,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"-m", "mark", "!", "--mark", observeMark,
							"-m", "state", "--state", "NEW",
							"-j", "NFLOG", "--nflog-group", "11",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add net log rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					}

					if observeContinue {
						if err := i.ipt.Append(
							i.netPacketIPTableContext, netChain,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					} else {
						if err := i.ipt.Append(
							i.netPacketIPTableContext, netChain,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"-j", "ACCEPT",
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					}

				case policy.Reject:
					if observeContinue {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext, netChain, 1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					} else {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext, netChain, 1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"-j", "DROP",
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					}

					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext,
							netChain,
							1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"-m", "mark", "!", "--mark", observeMark,
							"-m", "state", "--state", "NEW",
							"-j", "NFLOG", "--nflog-group", "11",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add net log rule for table %s, netChain %s: %s", i.netPacketIPTableContext, netChain, err)
						}
					}
				default:
					continue
				}
			}
		}
	}
	return nil
}

// addNetACLs adds iptables rules that manage traffic from external services. The
// explicit rules are added with the highest priority since they are direct allows.
func (i *Instance) addNetACLs(contextID, appChain, netChain string, rules policy.IPRuleList) error {

	if err := i.addTCPNetACLS(contextID, netChain, rules); err != nil {
		return fmt.Errorf("Unable to add tcp net acls: %s", err)
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
func (i *Instance) deleteChainRules(portSetName, appChain, netChain, tcpPorts, udpPorts string, mark string, uid string, proxyPort string, proxyPortSetName string, puType string) error {

	if i.mode == constants.LocalServer {
		if uid == "" {
			if udpPorts != "0" {
				// Delete the postrouting Nat rule for udp.
				err := i.processRulesFromList(i.getUDPNatRule(udpPorts), "Delete")
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

			return i.processRulesFromList(i.cgroupChainRules(appChain, netChain, mark, portSetName, tcpPorts, udpPorts, proxyPort, proxyPortSetName, appSection, netSection), "Delete")
		}

		return i.processRulesFromList(i.uidChainRules(portSetName, appChain, netChain, mark, uid), "Delete")
	}

	return i.processRulesFromList(i.chainRules(appChain, netChain, tcpPorts, proxyPort, proxyPortSetName), "Delete")
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

	// Add Trireme/Hostmode OUTPUT chain
	if i.mode == constants.LocalServer {

		err := i.ipt.Insert(
			i.appPacketIPTableContext,
			appChain, 1,
			"-j", HostModeOutput)
		if err != nil {
			return fmt.Errorf("unable to add default Hostmode-output app chain: %s", err)
		}

		err = i.ipt.Insert(
			i.appPacketIPTableContext,
			appChain, 1,
			"-j", NetworkSvcOutput)
		if err != nil {
			return fmt.Errorf("unable to add default networksvc-output app chain: %s", err)
		}

		err = i.ipt.Insert(
			i.appPacketIPTableContext,
			appChain, 1,
			"-j", TriremeOutput)
		if err != nil {
			return fmt.Errorf("unable to add default trireme-output app chain: %s", err)
		}

	}

	err := i.ipt.Insert(
		i.appPacketIPTableContext,
		appChain, 1,
		"-m", "connmark", "--mark", strconv.Itoa(int(constants.DefaultConnMark)),
		"-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at app: %s", err)
	}

	err = i.ipt.Insert(
		i.appPacketIPTableContext,
		appChain, 1,
		"-m", "set", "--match-set", targetNetworkSet, "dst",
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "NFQUEUE", "--queue-bypass", "--queue-balance", i.fqc.GetApplicationQueueSynAckStr())
	if err != nil {
		return fmt.Errorf("unable to add capture synack rule for table %s, chain %sr: %s", i.appPacketIPTableContext, i.appPacketIPTableSection, err)
	}

	err = i.ipt.Insert(
		i.appPacketIPTableContext,
		appChain, 1,
		"-m", "set", "--match-set", targetNetworkSet, "dst",
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "MARK", "--set-mark", strconv.Itoa(cgnetcls.Initialmarkval-1))
	if err != nil {
		return fmt.Errorf("unable to add capture synack rule for table %s, chain %s: %s", i.appPacketIPTableContext, i.appPacketIPTableSection, err)
	}

	err = i.ipt.Insert(
		i.appPacketIPTableContext,
		appChain, 1,
		"-m", "set", "--match-set", targetNetworkSet, "dst",
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "MARK", "--set-mark", strconv.Itoa(cgnetcls.Initialmarkval-1))
	if err != nil {
		return fmt.Errorf("unable to add capture synack rule for table %s, chain %s: %s", i.appPacketIPTableContext, i.appPacketIPTableSection, err)
	}

	if i.mode == constants.LocalServer {
		err = i.ipt.Insert(
			i.appPacketIPTableContext,
			i.appPacketIPTableSection, 1,
			"-j", uidchain)
		if err != nil {
			return fmt.Errorf("unable to add uid chain %s, chain %s: %s", i.appPacketIPTableContext, i.appPacketIPTableSection, err)
		}
	}

	err = i.ipt.Insert(
		i.appPacketIPTableContext,
		appChain, 1,
		"-m", "connmark", "--mark", strconv.Itoa(int(constants.DefaultConnMark)),
		"-j", "ACCEPT")

	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at net: %s", err)
	}

	// Add Trireme/Hostmode Input chains
	if i.mode == constants.LocalServer {
		// create a new chain and hang pus out of chain

		err = i.ipt.Insert(
			i.appPacketIPTableContext,
			netChain, 1,
			"-j", HostModeInput)
		if err != nil {
			return fmt.Errorf("unable to add default hostmode-input net chain: %s", err)
		}

		err = i.ipt.Insert(
			i.appPacketIPTableContext,
			netChain, 1,
			"-j", NetworkSvcInput)
		if err != nil {
			return fmt.Errorf("unable to add default networkSvc-input net chain: %s", err)
		}

		err = i.ipt.Insert(
			i.appPacketIPTableContext,
			netChain, 1,
			"-j", TriremeInput)
		if err != nil {
			return fmt.Errorf("unable to add default trireme-input net chain: %s", err)
		}

		err = i.ipt.Insert(
			i.appPacketIPTableContext,
			netChain, 1,
			"-j", uidInput)
		if err != nil {
			return fmt.Errorf("unable to add default uid-input net chain: %s", err)
		}
	}

	err = i.ipt.Insert(
		i.netPacketIPTableContext,
		netChain, 1,
		"-m", "set", "--match-set", targetNetworkSet, "src",
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN", "--tcp-option",
		"34", "-j", "NFQUEUE", "--queue-bypass", "--queue-balance", i.fqc.GetNetworkQueueSynStr())

	if err != nil {
		return fmt.Errorf("unable to add capture syn rule for table %s, chain %s: %s", i.appPacketIPTableContext, i.appPacketIPTableSection, err)
	}

	err = i.ipt.Insert(
		i.netPacketIPTableContext,
		netChain, 1,
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "NFQUEUE", "--queue-bypass", "--queue-balance", i.fqc.GetNetworkQueueSynAckStr())

	if err != nil {
		return fmt.Errorf("unable to add capture synack rule for table %s, chain %s: %s", i.appPacketIPTableContext, i.appPacketIPTableSection, err)
	}

	err = i.ipt.Insert(
		i.netPacketIPTableContext,
		netChain, 1,
		"-m", "connmark", "--mark", strconv.Itoa(int(constants.DefaultConnMark)),
		"-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("unable to add capture synack rule for table %s, chain %s: %s", i.appPacketIPTableContext, i.appPacketIPTableSection, err)
	}

	err = i.ipt.Insert(
		i.netPacketIPTableContext,
		netChain, 1,
		"-m", "set", "--match-set", targetNetworkSet, "dst",
		"-p", "udp",
		"-m", "string", "--algo", "bm", "--string", packet.UDPAuthMarker,
		"-j", "NFQUEUE", "--queue-bypass", "--queue-balance", i.fqc.GetNetworkQueueSynAckStr())
	if err != nil {
		return fmt.Errorf("unable to add capture udp handshake rule for table %s, chain %sr: %s", i.appPacketIPTableContext, i.appPacketIPTableSection, err)
	}

	err = i.ipt.Insert(i.appProxyIPTableContext,
		ipTableSectionPreRouting, 1,
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

	err = i.ipt.Insert(i.appPacketIPTableContext,
		i.netPacketIPTableSection, 1,
		"-j", proxyInputChain,
	)
	if err != nil {
		return fmt.Errorf("unable to add default allow for marked packets at net: %s", err)
	}

	err = i.ipt.Insert(i.appPacketIPTableContext,
		i.appPacketIPTableSection,
		1,
		"-j", proxyOutputChain,
	)
	if err != nil {
		return fmt.Errorf("unable to add proxy output chain: %s", err)
	}

	err = i.ipt.Insert(i.appPacketIPTableContext,
		i.appPacketIPTableSection,
		1,
		"-m", "mark",
		"--mark", strconv.Itoa(afinetrawsocket.ApplicationRawSocketMark),
		"-j", "ACCEPT",
	)
	if err != nil {
		return fmt.Errorf("unable to add application raw socket mark rule output chain: %s", err)
	}

	return nil
}

// CleanGlobalRules cleans the capture rules for SynAck packets
func (i *Instance) CleanGlobalRules() error {

	if err := i.ipt.Delete(
		i.appPacketIPTableContext,
		i.appPacketIPTableSection,
		"-m", "set", "--match-set", targetNetworkSet, "dst",
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "NFQUEUE", "--queue-bypass", "--queue-balance", i.fqc.GetApplicationQueueAckStr()); err != nil {
		zap.L().Debug("Can not clear the SynAck packet capcture app chain", zap.Error(err))
	}

	if err := i.ipt.Delete(
		i.netPacketIPTableContext,
		i.netPacketIPTableSection,
		"-m", "set", "--match-set", targetNetworkSet, "src",
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
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

func (i *Instance) removeProxyRules(natproxyTableContext string, proxyTableContext string, inputProxySection string, outputProxySection string, natProxyInputChain, natProxyOutputChain, proxyInputChain, proxyOutputChain string) (err error) {

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

	if err = i.ipt.Delete(natproxyTableContext, inputProxySection, "-j", natProxyInputChain); err != nil {
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

func (i *Instance) cleanACLs() error {

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
func (i *Instance) cleanTriremeChains(context string) error {

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

func (i *Instance) addNATExclusionACLs(appChain, netChain, cgroupMark, setName string, exclusions []string) error {
	destSetName, srvSetName := i.getSetNames(setName)
	for _, e := range exclusions {

		if err := i.ipt.Insert(
			i.appProxyIPTableContext, natProxyInputChain, 1,
			"-p", "tcp",
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
				"-p", "tcp",
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
				"-p", "tcp",
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
func (i *Instance) deleteNATExclusionACLs(appChain, netChain, cgroupMark, setName string, exclusions []string) error {

	destSetName, srvSetName := i.getSetNames(setName)
	for _, e := range exclusions {
		if err := i.ipt.Delete(
			i.appProxyIPTableContext, natProxyInputChain,
			"-p", "tcp",
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
				"-p", "tcp",
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
				"-p", "tcp",
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
