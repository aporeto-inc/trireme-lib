package iptablesctrl

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/controller/constants"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/packet"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls"
)

const observeMark = "39"

func (i *Instance) cgroupChainRules(appChain string, netChain string, mark string, port string, uid string, proxyPort string, proxyPortSetName string) [][]string {

	destSetName, srcSetName, srvSetName := i.getSetNames(proxyPortSetName)
	str := [][]string{
		{
			i.appPacketIPTableContext,
			i.appCgroupIPTableSection,
			"-m", "cgroup", "--cgroup", mark,
			"-m", "comment", "--comment", "Server-specific-chain",
			"-j", "MARK", "--set-mark", mark,
		},
		{
			i.appPacketIPTableContext,
			i.appCgroupIPTableSection,
			"-m", "cgroup", "--cgroup", mark,
			"-m", "comment", "--comment", "Server-specific-chain",
			"-j", appChain,
		},
		{
			i.appProxyIPTableContext,
			natProxyInputChain,
			"-p", "tcp",
			"-m", "mark", "!",
			"--mark", proxyMark,
			"-m", "set",
			"--match-set", srcSetName, "src,dst",
			"-j", "REDIRECT",
			"--to-port", proxyPort,
		},
		{
			i.appProxyIPTableContext,
			natProxyOutputChain,
			"-p", "tcp",
			"-m", "set",
			"--match-set", destSetName, "dst,dst",
			"-m", "mark", "!",
			"--mark", proxyMark,
			"-j", "REDIRECT",
			"--to-port", proxyPort,
		},
		{
			i.appProxyIPTableContext,
			natProxyOutputChain,
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
		{
			i.netPacketIPTableContext,
			proxyInputChain,
			"-p", "tcp",
			"-m", "set",
			"--match-set", srcSetName, "src,dst",
			"-j", "ACCEPT",
		},
		{
			i.netPacketIPTableContext,
			proxyInputChain,
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
		{
			i.netPacketIPTableContext,
			i.netPacketIPTableSection,
			"-p", "tcp",
			"-m", "multiport",
			"--destination-ports", port,
			"-m", "comment", "--comment", "Container-specific-chain",
			"-j", netChain,
		},
	}

	return str
}

func (i *Instance) uidChainRules(portSetName, appChain string, netChain string, mark string, port string, uid string, proxyPort string, proyPortSetName string) [][]string {

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
			i.netPacketIPTableSection,
			"-p", "tcp",
			"-m", "mark",
			"--mark", mark,
			"-m", "comment", "--comment", "Container-specific-chain 1",
			"-j", netChain,
		},
	}

	return str
}

// chainRules provides the list of rules that are used to send traffic to
// a particular chain
func (i *Instance) chainRules(appChain string, netChain string, port string, proxyPort string, proxyPortSetName string) [][]string {

	rules := [][]string{}
	destSetName, srcSetName, srvSetName := i.getSetNames(proxyPortSetName)

	rules = append(rules, []string{
		i.appPacketIPTableContext,
		i.appPacketIPTableSection,
		"-m", "comment", "--comment", "Container-specific-chain",
		"-j", appChain,
	})

	rules = append(rules, []string{
		i.netPacketIPTableContext,
		i.netPacketIPTableSection,
		"-m", "comment", "--comment", "Container-specific-chain",
		"-j", netChain,
	})
	proxyRules := [][]string{
		{
			i.appProxyIPTableContext,
			natProxyInputChain,
			"-p", "tcp",
			"-m", "mark", "!",
			"--mark", proxyMark,
			"-m", "set",
			"--match-set", srcSetName, "src,dst",
			"-j", "REDIRECT",
			"--to-port", proxyPort,
		},
		{
			i.appProxyIPTableContext,
			natProxyOutputChain,
			"-p", "tcp",
			"-m", "set",
			"--match-set", destSetName, "dst,dst",
			"-m", "mark", "!",
			"--mark", proxyMark,
			"-j", "REDIRECT",
			"--to-port", proxyPort,
		},
		{
			i.appProxyIPTableContext,
			natProxyOutputChain,
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
		{
			i.netPacketIPTableContext,
			proxyInputChain,
			"-p", "tcp",
			"-m", "set",
			"--match-set", srcSetName, "src,dst",
			"-j", "ACCEPT",
		},
		{
			i.netPacketIPTableContext,
			proxyInputChain,
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
	rules = append(rules, proxyRules...)
	return rules

}

//trapRules provides the packet trap rules to add/delete
func (i *Instance) trapRules(appChain string, netChain string) [][]string {

	rules := [][]string{}

	// Application Packets - SYN
	rules = append(rules, []string{
		i.appPacketIPTableContext, appChain,
		"-m", "set", "--match-set", targetNetworkSet, "dst",
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN",
		"-j", "NFQUEUE", "--queue-balance", i.fqc.GetApplicationQueueSynStr(),
	})

	// Application Packets - Evertyhing but SYN and SYN,ACK (first 4 packets). SYN,ACK is captured by global rule
	rules = append(rules, []string{
		i.appPacketIPTableContext, appChain,
		"-m", "set", "--match-set", targetNetworkSet, "dst",
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
		"-j", "NFQUEUE", "--queue-balance", i.fqc.GetApplicationQueueAckStr(),
	})

	rules = append(rules, []string{
		i.appPacketIPTableContext, appChain,
		"-m", "set", "--match-set", targetNetworkSet, "dst",
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "NFQUEUE", "--queue-balance", i.fqc.GetApplicationQueueAckStr(),
	})

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
	for _, cr := range rulelist {
		switch methodType {
		case "Append":
			if err := i.ipt.Append(cr[0], cr[1], cr[2:]...); err != nil {
				return fmt.Errorf("unable to %s rule for table %s and chain %s with error %s", methodType, cr[0], cr[1], err)
			}
		case "Insert":
			if err := i.ipt.Insert(cr[0], cr[1], 1, cr[2:]...); err != nil {
				return fmt.Errorf("unable to %s rule for table %s and chain %s with error %s", methodType, cr[0], cr[1], err)
			}
		case "Delete":
			if err := i.ipt.Delete(cr[0], cr[1], cr[2:]...); err != nil {
				zap.L().Warn("Unable to delete rule from chain", zap.Error(err))
			}
		default:
			return errors.New("invalid method type")
		}
	}
	return nil
}

// addChainrules implements all the iptable rules that redirect traffic to a chain
func (i *Instance) addChainRules(portSetName string, appChain string, netChain string, port string, mark string, uid string, proxyPort string, proxyPortSetName string) error {
	if i.mode == constants.LocalServer {
		if port != "0" || uid == "" {
			return i.processRulesFromList(i.cgroupChainRules(appChain, netChain, mark, port, uid, proxyPort, proxyPortSetName), "Append")
		}

		return i.processRulesFromList(i.uidChainRules(portSetName, appChain, netChain, mark, port, uid, proxyPort, proxyPortSetName), "Append")

	}

	return i.processRulesFromList(i.chainRules(appChain, netChain, port, proxyPort, proxyPortSetName), "Append")

}

// addPacketTrap adds the necessary iptables rules to capture control packets to user space
func (i *Instance) addPacketTrap(appChain string, netChain string, networks []string) error {

	return i.processRulesFromList(i.trapRules(appChain, netChain), "Append")

}

// addAppACLs adds a set of rules to the external services that are initiated
// by an application. The allow rules are inserted with highest priority.
func (i *Instance) addAppACLs(contextID, chain string, rules policy.IPRuleList) error {

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

			if proto == "udp" || proto == "tcp" {

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
							return fmt.Errorf("unable to add acl log rule for table %s, chain %s: %s", i.appPacketIPTableContext, chain, err)
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

			} else {

				switch rule.Policy.Action & (policy.Accept | policy.Reject) {
				case policy.Accept:

					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Append(
							i.appPacketIPTableContext,
							chain,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"-m", "state", "--state", "NEW",
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "NFLOG", "--nflog-group", "10",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add acl log rule for table %s, chain %s: %s", i.appPacketIPTableContext, chain, err)
						}
					}

					if observeContinue {
						if err := i.ipt.Append(
							i.appPacketIPTableContext, chain,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, chain, err)
						}
					} else {
						if err := i.ipt.Append(
							i.appPacketIPTableContext, chain,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"-j", "ACCEPT",
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, chain, err)
						}
					}

				case policy.Reject:
					if observeContinue {
						if err := i.ipt.Insert(
							i.appPacketIPTableContext, chain, 1,
							"-p", rule.Protocol,
							"-d", rule.Address,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, chain, err)
						}
					} else {
						if err := i.ipt.Insert(
							i.appPacketIPTableContext, chain, 1,
							"-p", rule.Protocol,
							"-d", rule.Address,
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
							"-m", "state", "--state", "NEW",
							"-m", "mark", "!", "--mark", observeMark,
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

	// Accept established connections
	if err := i.ipt.Append(
		i.appPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-p", "udp", "-m", "state", "--state", "ESTABLISHED",
		"-j", "ACCEPT"); err != nil {

		return fmt.Errorf("unable to add default udp acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, chain, err)
	}

	if err := i.ipt.Append(
		i.appPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "ESTABLISHED",
		"-j", "ACCEPT"); err != nil {

		return fmt.Errorf("unable to add default tcp acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, chain, err)
	}

	// Log everything else
	if err := i.ipt.Append(
		i.appPacketIPTableContext,
		chain,
		"-d", "0.0.0.0/0",
		"-m", "state", "--state", "NEW",
		"-j", "NFLOG", "--nflog-group", "10",
		"--nflog-prefix", policy.DefaultLogPrefix(contextID),
	); err != nil {
		return fmt.Errorf("unable to add acl log rule for table %s, chain %s: %s", i.appPacketIPTableContext, chain, err)
	}

	// Drop everything else
	if err := i.ipt.Append(
		i.appPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-j", "DROP"); err != nil {

		return fmt.Errorf("unable to add default drop acl rule for table %s, chain %s: %s", i.appPacketIPTableContext, chain, err)
	}

	return nil
}

// addNetACLs adds iptables rules that manage traffic from external services. The
// explicit rules are added with the highest priority since they are direct allows.
func (i *Instance) addNetACLs(contextID, chain string, rules policy.IPRuleList) error {

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

			if proto == "udp" || proto == "tcp" {

				switch rule.Policy.Action & (policy.Accept | policy.Reject) {
				case policy.Accept:

					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Append(
							i.netPacketIPTableContext,
							chain,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-m", "state", "--state", "NEW",
							"-j", "NFLOG", "--nflog-group", "11",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add net log rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
						}
					}

					if observeContinue {
						if err := i.ipt.Append(
							i.netPacketIPTableContext, chain,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
						}
					} else {
						if err := i.ipt.Append(
							i.netPacketIPTableContext, chain,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-j", "ACCEPT",
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
						}
					}

				case policy.Reject:
					if observeContinue {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext, chain, 1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
						}
					} else {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext, chain, 1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-j", "DROP",
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
						}
					}

					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext,
							chain,
							1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"--dport", rule.Port,
							"-m", "mark", "!", "--mark", observeMark,
							"-m", "state", "--state", "NEW",
							"-j", "NFLOG", "--nflog-group", "11",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add net log rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
						}
					}

				default:
					continue
				}

			} else {

				switch rule.Policy.Action & (policy.Accept | policy.Reject) {
				case policy.Accept:
					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Append(
							i.netPacketIPTableContext,
							chain,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"-m", "mark", "!", "--mark", observeMark,
							"-m", "state", "--state", "NEW",
							"-j", "NFLOG", "--nflog-group", "11",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add net log rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
						}
					}

					if observeContinue {
						if err := i.ipt.Append(
							i.netPacketIPTableContext, chain,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
						}
					} else {
						if err := i.ipt.Append(
							i.netPacketIPTableContext, chain,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"-j", "ACCEPT",
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
						}
					}

				case policy.Reject:
					if observeContinue {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext, chain, 1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"-m", "mark", "!", "--mark", observeMark,
							"-j", "MARK", "--set-mark", observeMark,
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
						}
					} else {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext, chain, 1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"-j", "DROP",
						); err != nil {
							return fmt.Errorf("unable to add net acl rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
						}
					}

					if rule.Policy.Action&policy.Log > 0 || observeContinue {
						if err := i.ipt.Insert(
							i.netPacketIPTableContext,
							chain,
							1,
							"-p", rule.Protocol,
							"-s", rule.Address,
							"-m", "mark", "!", "--mark", observeMark,
							"-m", "state", "--state", "NEW",
							"-j", "NFLOG", "--nflog-group", "11",
							"--nflog-prefix", rule.Policy.LogPrefix(contextID),
						); err != nil {
							return fmt.Errorf("unable to add net log rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
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
		i.netPacketIPTableContext, chain,
		"-s", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "ESTABLISHED",
		"-j", "ACCEPT",
	); err != nil {

		return fmt.Errorf("unable to add net acl rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
	}

	if err := i.ipt.Append(
		i.netPacketIPTableContext, chain,
		"-s", "0.0.0.0/0",
		"-p", "udp", "-m", "state", "--state", "ESTABLISHED",
		"-j", "ACCEPT",
	); err != nil {

		return fmt.Errorf("unable to add net acl rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
	}

	// Log everything
	if err := i.ipt.Append(
		i.netPacketIPTableContext,
		chain,
		"-s", "0.0.0.0/0",
		"-m", "state", "--state", "NEW",
		"-j", "NFLOG", "--nflog-group", "11",
		"--nflog-prefix", policy.DefaultLogPrefix(contextID),
	); err != nil {
		return fmt.Errorf("unable to add net log rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
	}

	// Drop everything else
	if err := i.ipt.Append(
		i.netPacketIPTableContext, chain,
		"-s", "0.0.0.0/0",
		"-j", "DROP",
	); err != nil {

		return fmt.Errorf("unable to add net acl rule for table %s, chain %s: %s", i.netPacketIPTableContext, chain, err)
	}

	return nil
}

// deleteChainRules deletes the rules that send traffic to our chain
func (i *Instance) deleteChainRules(contextID, appChain, netChain, port string, mark string, uid string, proxyPort string, proxyPortSetName string) error {

	if i.mode == constants.LocalServer {
		if uid == "" {
			return i.processRulesFromList(i.cgroupChainRules(appChain, netChain, mark, port, uid, proxyPort, proxyPortSetName), "Delete")
		}
		portSetName := puPortSetName(contextID, PuPortSet)
		return i.processRulesFromList(i.uidChainRules(portSetName, appChain, netChain, mark, port, uid, proxyPort, proxyPortSetName), "Delete")
	}

	return i.processRulesFromList(i.chainRules(appChain, netChain, port, proxyPort, proxyPortSetName), "Delete")
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
		"-m", "set", "--match-set", targetNetworkSet, "src",
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
		zap.L().Debug("Failed to remove rule on", zap.String("TableContext", natproxyTableContext), zap.String("TableSection", inputProxySection), zap.String("Target", natProxyInputChain), zap.Error(err))
	}

	if err = i.ipt.Delete(natproxyTableContext, outputProxySection, "-j", natProxyOutputChain); err != nil {
		zap.L().Debug("Failed to remove rule on", zap.String("TableContext", natproxyTableContext), zap.String("TableSection", outputProxySection), zap.String("Target", natProxyOutputChain), zap.Error(err))
	}

	if err = i.ipt.ClearChain(natproxyTableContext, natProxyInputChain); err != nil {
		zap.L().Warn("Failed to clear chain", zap.String("TableContext", natproxyTableContext), zap.String("Chain", natProxyInputChain))
	}

	if err = i.ipt.ClearChain(natproxyTableContext, natProxyOutputChain); err != nil {
		zap.L().Warn("Failed to clear chain", zap.String("TableContext", natproxyTableContext), zap.String("Chain", natProxyOutputChain))
	}

	if err = i.ipt.DeleteChain(natproxyTableContext, natProxyInputChain); err != nil {
		zap.L().Warn("Failed to delete chain", zap.String("TableContext", natproxyTableContext), zap.String("Chain", natProxyInputChain))
	}

	if err = i.ipt.DeleteChain(natproxyTableContext, natProxyOutputChain); err != nil {
		zap.L().Warn("Failed to delete chain", zap.String("TableContext", natproxyTableContext), zap.String("Chain", natProxyOutputChain))
	}

	//Nat table is clean
	if err = i.ipt.ClearChain(proxyTableContext, proxyInputChain); err != nil {
		zap.L().Warn("Failed to clear chain", zap.String("TableContext", proxyTableContext), zap.String("Chain", proxyInputChain))
	}

	if err = i.ipt.DeleteChain(proxyTableContext, proxyInputChain); err != nil {
		zap.L().Warn("Failed to delete chain", zap.String("TableContext", proxyTableContext), zap.String("Chain", proxyInputChain))
	}

	if err = i.ipt.ClearChain(proxyTableContext, proxyOutputChain); err != nil {
		zap.L().Warn("Failed to clear chain", zap.String("TableContext", proxyTableContext), zap.String("Chain", proxyOutputChain))
	}

	if err = i.ipt.DeleteChain(proxyTableContext, proxyOutputChain); err != nil {
		zap.L().Warn("Failed to clear chain", zap.String("TableContext", proxyTableContext), zap.String("Chain", proxyOutputChain))
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
			"-p", "tcp", "!", "--tcp-option", strconv.Itoa(int(packet.TCPAuthenticationOption)),
			"-j", "ACCEPT",
		); err != nil {
			return fmt.Errorf("unable to add exclusion rule for table %s, chain %s, ip %s: %s", i.appPacketIPTableContext, netChain, e, err)
		}
	}

	return nil
}
