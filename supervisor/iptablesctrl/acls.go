package iptablesctrl

import (
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/policy"
)

func (i *Instance) cgroupChainRules(appChain string, netChain string, mark string, port string, uid string) [][]string {

	str := [][]string{
		{
			i.appAckPacketIPTableContext,
			i.appCgroupIPTableSection,
			"-m", "cgroup", "--cgroup", mark,
			"-m", "comment", "--comment", "Server-specific-chain",
			"-j", "MARK", "--set-mark", mark,
		},
		{
			i.appAckPacketIPTableContext,
			i.appCgroupIPTableSection,
			"-m", "cgroup", "--cgroup", mark,
			"-m", "comment", "--comment", "Server-specific-chain",
			"-j", appChain,
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

func (i *Instance) uidChainRules(appChain string, netChain string, mark string, port string, uid string) [][]string {

	str := [][]string{
		{
			i.appAckPacketIPTableContext,
			uidchain,
			"-m", "owner", "--uid-owner", uid, "-j", "MARK", "--set-mark", mark,
		},
		{
			i.appAckPacketIPTableContext,
			uidchain,
			"-m", "cgroup", "--cgroup", mark,
			"-m", "comment", "--comment", "Server-specific-chain",
			"-j", "MARK", "--set-mark", mark,
		},
		{
			i.appAckPacketIPTableContext,
			uidchain,
			"-m", "mark", "--mark", mark,
			"-m", "comment", "--comment", "Server-specific-chain",
			"-j", appChain,
		},
	}
	if port != "0" {
		str = append(str, []string{
			i.netPacketIPTableContext,
			i.netPacketIPTableSection,
			"-p", "tcp",
			"-m", "multiport",
			"--destination-ports", port,
			"-m", "comment", "--comment", "Container-specific-chain 1",
			"-j", netChain,
		})
	} else {
		str = append(str, []string{
			i.netPacketIPTableContext,
			i.netPacketIPTableSection,
			"-p", "tcp",
			"-m", "comment", "--comment", "Container-specific-chain",
			"-j", netChain,
		})
	}

	return str
}

// chainRules provides the list of rules that are used to send traffic to
// a particular chain
func (i *Instance) chainRules(appChain string, netChain string, ip string) [][]string {

	rules := [][]string{}

	if i.mode == constants.LocalContainer {
		rules = append(rules, []string{
			i.appPacketIPTableContext,
			i.appPacketIPTableSection,
			"-s", ip,
			"-m", "comment", "--comment", "Container-specific-chain",
			"-j", appChain,
		})
	}

	rules = append(rules, []string{
		i.appAckPacketIPTableContext,
		i.appPacketIPTableSection,
		"-s", ip,
		"-m", "comment", "--comment", "Container-specific-chain",
		"-j", appChain,
	})

	rules = append(rules, []string{
		i.netPacketIPTableContext,
		i.netPacketIPTableSection,
		"-d", ip,
		"-m", "comment", "--comment", "Container-specific-chain",
		"-j", netChain,
	})

	return rules

}

//trapRules provides the packet trap rules to add/delete
func (i *Instance) trapRules(appChain string, netChain string) [][]string {

	rules := [][]string{}

	if i.mode == constants.LocalContainer {
		// Application Packets - SYN
		rules = append(rules, []string{
			i.appPacketIPTableContext, appChain,
			"-m", "set", "--match-set", targetNetworkSet, "dst",
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "NFQUEUE", "--queue-balance", i.fqc.GetApplicationQueueSynStr(),
		})
		// Application Packets - Evertyhing but SYN (first 4 packets)
		rules = append(rules, []string{
			i.appAckPacketIPTableContext, appChain,
			"-m", "set", "--match-set", targetNetworkSet, "dst",
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", i.fqc.GetApplicationQueueAckStr(),
		})
		//Moving to global rule
		// Network Packets - SYN
		rules = append(rules, []string{
			i.netPacketIPTableContext, netChain,
			"-m", "set", "--match-set", targetNetworkSet, "src",
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN",
			"-j", "NFQUEUE", "--queue-balance", i.fqc.GetNetworkQueueSynStr(),
		})
		// // Network Packets - Evertyhing but SYN (first 4 packets)
		rules = append(rules, []string{
			i.netPacketIPTableContext, netChain,
			"-m", "set", "--match-set", targetNetworkSet, "src",
			"-p", "tcp",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", i.fqc.GetNetworkQueueAckStr(),
		})

	} else {
		// Application Packets - SYN
		rules = append(rules, []string{
			i.appAckPacketIPTableContext, appChain,
			"-m", "set", "--match-set", targetNetworkSet, "dst",
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN",
			"-j", "NFQUEUE", "--queue-balance", i.fqc.GetApplicationQueueSynStr(),
		})
		rules = append(rules, []string{
			i.appAckPacketIPTableContext, appChain,
			"-m", "set", "--match-set", targetNetworkSet, "dst",
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
			"-j", "NFQUEUE", "--queue-balance", i.fqc.GetApplicationQueueSynStr(),
		})
		// Application Packets - Evertyhing but SYN and SYN,ACK (first 4 packets). SYN,ACK is captured by global rule
		rules = append(rules, []string{
			i.appAckPacketIPTableContext, appChain,
			"-m", "set", "--match-set", targetNetworkSet, "dst",
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
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
			"-p", "tcp", "--tcp-flags", "SYN,ACK,PSH", "ACK",
			"-j", "NFQUEUE", "--queue-balance", i.fqc.GetNetworkQueueAckStr(),
		})
	}
	return rules
}

// addContainerChain adds a chain for the specific container and redirects traffic there
// This simplifies significantly the management and makes the iptable rules more readable
// All rules related to a container are contained within the dedicated chain
func (i *Instance) addContainerChain(appChain string, netChain string) error {

	if i.mode == constants.LocalContainer {
		if err := i.ipt.NewChain(i.appPacketIPTableContext, appChain); err != nil {
			return fmt.Errorf("Failed to add chain %s of context %s : %s", appChain, i.appPacketIPTableContext, err.Error())
		}
	}

	if err := i.ipt.NewChain(i.appAckPacketIPTableContext, appChain); err != nil {
		return fmt.Errorf("Failed to add chain %s of context %s : %s", appChain, i.appPacketIPTableContext, err.Error())
	}

	if err := i.ipt.NewChain(i.netPacketIPTableContext, netChain); err != nil {
		return fmt.Errorf("Failed to add  netChain %s of context %s : %s", netChain, i.netPacketIPTableContext, err.Error())
	}

	return nil
}

func (i *Instance) processRulesFromList(rulelist [][]string, methodType string) error {
	for _, cr := range rulelist {
		switch methodType {
		case "Append":
			if err := i.ipt.Append(cr[0], cr[1], cr[2:]...); err != nil {
				return fmt.Errorf("Failed to %s rule for table %s and chain %s with error %s ", methodType, cr[0], cr[1], err.Error())
			}
		case "Insert":
			if err := i.ipt.Insert(cr[0], cr[1], 1, cr[2:]...); err != nil {
				return fmt.Errorf("Failed to %s rule for table %s and chain %s with error %s ", methodType, cr[0], cr[1], err.Error())
			}
		case "Delete":
			if err := i.ipt.Delete(cr[0], cr[1], cr[2:]...); err != nil {
				zap.L().Warn("Failed to delete rule from chain", zap.Error(err))
			}
		default:
			return fmt.Errorf("Invalid method type")
		}
	}
	return nil
}

// addChainrules implements all the iptable rules that redirect traffic to a chain
func (i *Instance) addChainRules(appChain string, netChain string, ip string, port string, mark string, uid string) error {

	if i.mode == constants.LocalServer {
		if port != "0" || uid == "" {
			return i.processRulesFromList(i.cgroupChainRules(appChain, netChain, mark, port, uid), "Append")
		}
		return i.processRulesFromList(i.uidChainRules(appChain, netChain, mark, port, uid), "Append")

	}

	return i.processRulesFromList(i.chainRules(appChain, netChain, ip), "Append")

}

// addPacketTrap adds the necessary iptables rules to capture control packets to user space
func (i *Instance) addPacketTrap(appChain string, netChain string, ip string, networks []string) error {

	return i.processRulesFromList(i.trapRules(appChain, netChain), "Append")

}

// addAppACLs adds a set of rules to the external services that are initiated
// by an application. The allow rules are inserted with highest priority.
func (i *Instance) addAppACLs(contextID, chain, ip string, rules policy.IPRuleList) error {

	for _, rule := range rules {

		proto := strings.ToLower(rule.Protocol)

		if proto == "udp" || proto == "tcp" {

			switch rule.Policy.Action & (policy.Accept | policy.Reject) {
			case policy.Accept:

				if rule.Policy.Action&policy.Log > 0 {
					if err := i.ipt.Append(
						i.appAckPacketIPTableContext,
						chain,
						"-p", rule.Protocol,
						"-d", rule.Address,
						"--dport", rule.Port,
						"-m", "state", "--state", "NEW",
						"-j", "NFLOG", "--nflog-group", "10",
						"--nflog-prefix", contextID+":"+rule.Policy.PolicyID+":"+rule.Policy.ServiceID+rule.Policy.Action.ShortActionString(),
					); err != nil {
						return fmt.Errorf("Failed to add acl log rule for table %s, chain %s, with %s", i.appAckPacketIPTableContext, chain, err.Error())
					}
				}

				if err := i.ipt.Append(
					i.appAckPacketIPTableContext, chain,
					"-p", rule.Protocol, "-m", "state", "--state", "NEW",
					"-d", rule.Address,
					"--dport", rule.Port,
					"-j", "ACCEPT",
				); err != nil {
					return fmt.Errorf("Failed to add acl rule for table %s, chain %s, with %s", i.appAckPacketIPTableContext, chain, err.Error())
				}

			case policy.Reject:
				if err := i.ipt.Insert(
					i.appAckPacketIPTableContext, chain, 1,
					"-p", rule.Protocol, "-m", "state", "--state", "NEW",
					"-d", rule.Address,
					"--dport", rule.Port,
					"-j", "DROP",
				); err != nil {
					return fmt.Errorf("Failed to add acl rule for table %s, chain %s, with %s", i.appAckPacketIPTableContext, chain, err.Error())
				}

				if rule.Policy.Action&policy.Log > 0 {
					if err := i.ipt.Insert(
						i.appAckPacketIPTableContext,
						chain,
						1,
						"-p", rule.Protocol,
						"-d", rule.Address,
						"--dport", rule.Port,
						"-m", "state", "--state", "NEW",
						"-j", "NFLOG", "--nflog-group", "10",
						"--nflog-prefix", contextID+":"+rule.Policy.PolicyID+":"+rule.Policy.ServiceID+rule.Policy.Action.ShortActionString(),
					); err != nil {
						return fmt.Errorf("Failed to add acl log rule for table %s, chain %s, with %s", i.appAckPacketIPTableContext, chain, err.Error())
					}
				}

			default:
				continue
			}

		} else {

			switch rule.Policy.Action & (policy.Accept | policy.Reject) {
			case policy.Accept:

				if rule.Policy.Action&policy.Log > 0 {
					if err := i.ipt.Append(
						i.appAckPacketIPTableContext,
						chain,
						"-p", rule.Protocol,
						"-d", rule.Address,
						"-m", "state", "--state", "NEW",
						"-j", "NFLOG", "--nflog-group", "10",
						"--nflog-prefix", contextID+":"+rule.Policy.PolicyID+":"+rule.Policy.ServiceID+rule.Policy.Action.ShortActionString(),
					); err != nil {
						return fmt.Errorf("Failed to add acl log rule for table %s, chain %s, with %s", i.appAckPacketIPTableContext, chain, err.Error())
					}
				}

				if err := i.ipt.Append(
					i.appAckPacketIPTableContext, chain,
					"-p", rule.Protocol,
					"-d", rule.Address,
					"-j", "ACCEPT",
				); err != nil {
					return fmt.Errorf("Failed to add acl rule for table %s, chain %s, with %s", i.appAckPacketIPTableContext, chain, err.Error())
				}

			case policy.Reject:
				if err := i.ipt.Insert(
					i.appAckPacketIPTableContext, chain, 1,
					"-p", rule.Protocol,
					"-d", rule.Address,
					"-j", "DROP",
				); err != nil {
					return fmt.Errorf("Failed to add acl rule for table %s, chain %s, with error: %s", i.appAckPacketIPTableContext, chain, err.Error())
				}

				if rule.Policy.Action&policy.Log > 0 {
					if err := i.ipt.Insert(
						i.appAckPacketIPTableContext,
						chain,
						1,
						"-p", rule.Protocol,
						"-d", rule.Address,
						"-m", "state", "--state", "NEW",
						"-j", "NFLOG", "--nflog-group", "10",
						"--nflog-prefix", contextID+":"+rule.Policy.PolicyID+":"+rule.Policy.ServiceID+rule.Policy.Action.ShortActionString(),
					); err != nil {
						return fmt.Errorf("Failed to add acl log rule for table %s, chain %s, with %s", i.appAckPacketIPTableContext, chain, err.Error())
					}
				}
			default:
				continue
			}

		}
	}

	// Accept established connections
	if err := i.ipt.Append(
		i.appAckPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-p", "udp", "-m", "state", "--state", "ESTABLISHED",
		"-j", "ACCEPT"); err != nil {

		return fmt.Errorf("Failed to add default udp acl rule for table %s, chain %s, with error: %s", i.appAckPacketIPTableContext, chain, err.Error())
	}

	if err := i.ipt.Append(
		i.appAckPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "ESTABLISHED",
		"-j", "ACCEPT"); err != nil {

		return fmt.Errorf("Failed to add default tcp acl rule for table %s, chain %s, with error: %s", i.appAckPacketIPTableContext, chain, err.Error())
	}

	// Log everything else
	if err := i.ipt.Append(
		i.appAckPacketIPTableContext,
		chain,
		"-d", "0.0.0.0/0",
		"-m", "state", "--state", "NEW",
		"-j", "NFLOG", "--nflog-group", "10",
		"--nflog-prefix", contextID+":default:defaultr",
	); err != nil {
		return fmt.Errorf("Failed to add acl log rule for table %s, chain %s, with %s", i.appAckPacketIPTableContext, chain, err.Error())
	}

	// Drop everything else
	if err := i.ipt.Append(
		i.appAckPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-j", "DROP"); err != nil {

		return fmt.Errorf("Failed to add default drop acl rule for table %s, chain %s, with error: %s", i.appAckPacketIPTableContext, chain, err.Error())
	}

	return nil
}

// addNetACLs adds iptables rules that manage traffic from external services. The
// explicit rules are added with the highest priority since they are direct allows.
func (i *Instance) addNetACLs(contextID, chain, ip string, rules policy.IPRuleList) error {

	for _, rule := range rules {

		proto := strings.ToLower(rule.Protocol)

		if proto == "udp" || proto == "tcp" {

			switch rule.Policy.Action & (policy.Accept | policy.Reject) {
			case policy.Accept:

				if rule.Policy.Action&policy.Log > 0 {
					if err := i.ipt.Append(
						i.netPacketIPTableContext,
						chain,
						"-p", rule.Protocol,
						"-s", rule.Address,
						"--dport", rule.Port,
						"-m", "state", "--state", "NEW",
						"-j", "NFLOG", "--nflog-group", "11",
						"--nflog-prefix", contextID+":"+rule.Policy.PolicyID+":"+rule.Policy.ServiceID+rule.Policy.Action.ShortActionString(),
					); err != nil {
						return fmt.Errorf("Failed to add net log rule for table %s, chain %s, with %s", i.netPacketIPTableContext, chain, err.Error())
					}
				}

				if err := i.ipt.Append(
					i.netPacketIPTableContext, chain,
					"-p", rule.Protocol,
					"-s", rule.Address,
					"--dport", rule.Port,
					"-j", "ACCEPT",
				); err != nil {

					return fmt.Errorf("Failed to add net acl rule for table %s, chain %s, with error: %s", i.netPacketIPTableContext, chain, err.Error())
				}
			case policy.Reject:
				if err := i.ipt.Insert(
					i.netPacketIPTableContext, chain, 1,
					"-p", rule.Protocol,
					"-s", rule.Address,
					"--dport", rule.Port,
					"-j", "DROP",
				); err != nil {

					return fmt.Errorf("Failed to add net acl rule for table %s, chain %s, with error: %s", i.netPacketIPTableContext, chain, err.Error())
				}

				if rule.Policy.Action&policy.Log > 0 {
					if err := i.ipt.Insert(
						i.netPacketIPTableContext,
						chain,
						1,
						"-p", rule.Protocol,
						"-s", rule.Address,
						"--dport", rule.Port,
						"-m", "state", "--state", "NEW",
						"-j", "NFLOG", "--nflog-group", "11",
						"--nflog-prefix", contextID+":"+rule.Policy.PolicyID+":"+rule.Policy.ServiceID+rule.Policy.Action.ShortActionString(),
					); err != nil {
						return fmt.Errorf("Failed to add net log rule for table %s, chain %s, with %s", i.netPacketIPTableContext, chain, err.Error())
					}
				}

			default:
				continue
			}

		} else {

			switch rule.Policy.Action & (policy.Accept | policy.Reject) {
			case policy.Accept:
				if rule.Policy.Action&policy.Log > 0 {
					if err := i.ipt.Append(
						i.netPacketIPTableContext,
						chain,
						"-p", rule.Protocol,
						"-s", rule.Address,
						"-m", "state", "--state", "NEW",
						"-j", "NFLOG", "--nflog-group", "11",
						"--nflog-prefix", contextID+":"+rule.Policy.PolicyID+":"+rule.Policy.ServiceID+rule.Policy.Action.ShortActionString(),
					); err != nil {
						return fmt.Errorf("Failed to add net log rule for table %s, chain %s, with %s", i.netPacketIPTableContext, chain, err.Error())
					}
				}

				if err := i.ipt.Append(
					i.netPacketIPTableContext, chain,
					"-p", rule.Protocol,
					"-s", rule.Address,
					"-j", "ACCEPT",
				); err != nil {

					return fmt.Errorf("Failed to add net acl rule for table %s, chain %s, with error: %s", i.netPacketIPTableContext, chain, err.Error())
				}
			case policy.Reject:
				if err := i.ipt.Insert(
					i.netPacketIPTableContext, chain, 1,
					"-p", rule.Protocol,
					"-s", rule.Address,
					"-j", "DROP",
				); err != nil {

					return fmt.Errorf("Failed to add net acl rule for table %s, chain %s, with error: %s", i.netPacketIPTableContext, chain, err.Error())
				}

				if rule.Policy.Action&policy.Log > 0 {
					if err := i.ipt.Insert(
						i.netPacketIPTableContext,
						chain,
						1,
						"-p", rule.Protocol,
						"-s", rule.Address,
						"-m", "state", "--state", "NEW",
						"-j", "NFLOG", "--nflog-group", "11",
						"--nflog-prefix", contextID+":"+rule.Policy.PolicyID+":"+rule.Policy.ServiceID+rule.Policy.Action.ShortActionString(),
					); err != nil {
						return fmt.Errorf("Failed to add net log rule for table %s, chain %s, with %s", i.netPacketIPTableContext, chain, err.Error())
					}
				}
			default:
				continue
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

		return fmt.Errorf("Failed to add net acl rule for table %s, chain %s, with error: %s", i.netPacketIPTableContext, chain, err.Error())
	}

	if err := i.ipt.Append(
		i.netPacketIPTableContext, chain,
		"-s", "0.0.0.0/0",
		"-p", "udp", "-m", "state", "--state", "ESTABLISHED",
		"-j", "ACCEPT",
	); err != nil {

		return fmt.Errorf("Failed to add net acl rule for table %s, chain %s, with error: %s", i.netPacketIPTableContext, chain, err.Error())
	}

	// Log everything
	if err := i.ipt.Append(
		i.netPacketIPTableContext,
		chain,
		"-s", "0.0.0.0/0",
		"-m", "state", "--state", "NEW",
		"-j", "NFLOG", "--nflog-group", "11",
		"--nflog-prefix", contextID+":default:defaultr",
	); err != nil {
		return fmt.Errorf("Failed to add net log rule for table %s, chain %s, with %s", i.netPacketIPTableContext, chain, err.Error())
	}

	// Drop everything else
	if err := i.ipt.Append(
		i.netPacketIPTableContext, chain,
		"-s", "0.0.0.0/0",
		"-j", "DROP",
	); err != nil {

		return fmt.Errorf("Failed to add net acl rule for table %s, chain %s, with error: %s", i.netPacketIPTableContext, chain, err.Error())
	}

	return nil
}

// deleteChainRules deletes the rules that send traffic to our chain
func (i *Instance) deleteChainRules(appChain, netChain, ip string, port string, mark string, uid string) error {

	if i.mode == constants.LocalServer {
		if uid == "" {
			return i.processRulesFromList(i.cgroupChainRules(appChain, netChain, mark, port, uid), "Delete")
		}
		return i.processRulesFromList(i.uidChainRules(appChain, netChain, mark, port, uid), "Delete")

	}

	return i.processRulesFromList(i.chainRules(appChain, netChain, ip), "Delete")
}

// deleteAllContainerChains removes all the container specific chains and basic rules
func (i *Instance) deleteAllContainerChains(appChain, netChain string) error {

	if err := i.ipt.ClearChain(i.appPacketIPTableContext, appChain); err != nil {
		zap.L().Warn("Failed to clear the container specific chain",
			zap.String("appChain", appChain),
			zap.String("context", i.appPacketIPTableContext),
			zap.Error(err),
		)
	}

	if err := i.ipt.DeleteChain(i.appPacketIPTableContext, appChain); err != nil {
		zap.L().Warn("Failed to delete the container app packet chain",
			zap.String("appChain", appChain),
			zap.String("context", i.appPacketIPTableContext),
			zap.Error(err),
		)
	}

	if err := i.ipt.ClearChain(i.appAckPacketIPTableContext, appChain); err != nil {
		zap.L().Warn("Failed to clear the container ack packets chain",
			zap.String("appChain", appChain),
			zap.String("context", i.appAckPacketIPTableContext),
			zap.Error(err),
		)
	}

	if err := i.ipt.DeleteChain(i.appAckPacketIPTableContext, appChain); err != nil {
		zap.L().Warn("Failed to delete the container ack packets chain",
			zap.String("appChain", appChain),
			zap.String("context", i.appAckPacketIPTableContext),
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
		i.appAckPacketIPTableContext,
		appChain, 1,
		"-m", "set", "--match-set", targetNetworkSet, "dst",
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "NFQUEUE", "--queue-bypass", "--queue-balance", i.fqc.GetApplicationQueueSynAckStr())

	if err != nil {
		return fmt.Errorf("Failed to add capture SynAck rule for table %s, chain %s, with error: %s", i.appAckPacketIPTableContext, i.appPacketIPTableSection, err.Error())
	}

	err = i.ipt.Insert(
		i.appAckPacketIPTableContext,
		appChain, 1,
		"-m", "set", "--match-set", targetNetworkSet, "dst",
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "MARK", "--set-mark", strconv.Itoa(cgnetcls.Initialmarkval-1))
	if err != nil {
		return fmt.Errorf("Failed to add capture SynAck rule for table %s, chain %s, with error: %s", i.appAckPacketIPTableContext, i.appPacketIPTableSection, err.Error())
	}

	err = i.ipt.Insert(
		i.netPacketIPTableContext,
		netChain, 1,
		"-m", "set", "--match-set", targetNetworkSet, "src",
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "NFQUEUE", "--queue-bypass", "--queue-balance", i.fqc.GetNetworkQueueSynAckStr())

	if err != nil {
		return fmt.Errorf("Failed to add capture SynAck rule for table %s, chain %s, with error: %s", i.appAckPacketIPTableContext, i.appPacketIPTableSection, err.Error())
	}

	err = i.ipt.Insert(
		i.appAckPacketIPTableContext,
		appChain, 1,
		"-m", "connmark", "--mark", strconv.Itoa(int(constants.DefaultConnMark)),
		"-j", "ACCEPT")

	if err != nil {
		return fmt.Errorf("Failed to add default allow for marked packets at app ")
	}

	err = i.ipt.Insert(
		i.netPacketIPTableContext,
		netChain, 1,
		"-m", "connmark", "--mark", strconv.Itoa(int(constants.DefaultConnMark)),
		"-j", "ACCEPT")

	if err != nil {
		return fmt.Errorf("Failed to add default allow for marked packets at net")
	}

	return nil

}

// CleanGlobalRules cleans the capture rules for SynAck packets
func (i *Instance) CleanGlobalRules() error {

	if err := i.ipt.Delete(
		i.appAckPacketIPTableContext,
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
		i.appAckPacketIPTableContext,
		i.appPacketIPTableSection,
		"-m", "connmark", "--mark", strconv.Itoa(int(constants.DefaultConnMark)),
		"-j", "ACCEPT"); err != nil {

		zap.L().Debug("Can not clear the global app mark rule", zap.Error(err))
		return fmt.Errorf("Failed to add default allow for marked packets at app ")
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

	if err := i.ipt.ClearChain(i.appAckPacketIPTableContext, i.appSynAckIPTableSection); err != nil {
		zap.L().Debug("Can not clear the SynAck packet capcture app chain", zap.Error(err))
	}

	if err := i.ipt.ClearChain(i.netPacketIPTableContext, i.netPacketIPTableSection); err != nil {
		zap.L().Debug("Can not clear the SynAck packet capcture net chain", zap.Error(err))
	}
	//We installed UID CHAINS with synack lets remove it here
	if err := i.ipt.ClearChain(i.appAckPacketIPTableContext, uidchain); err != nil {
		zap.L().Debug("Cannot clear UID Chain", zap.Error(err))
	}
	if err := i.ipt.DeleteChain(i.appAckPacketIPTableContext, uidchain); err != nil {
		zap.L().Debug("Cannot delete UID Chain", zap.Error(err))
	}
	return nil
}

// acceptMarkedPackets installs the rules to accept all marked packets
func (i *Instance) acceptMarkedPackets() error {

	if i.mode != constants.LocalContainer {
		return nil
	}

	return i.ipt.Insert(
		i.appAckPacketIPTableContext,
		i.appPacketIPTableSection, 1,
		"-m", "mark",
		"--mark", strconv.Itoa(i.fqc.GetMarkValue()),
		"-j", "ACCEPT")
}

func (i *Instance) removeMarkRule() error {

	if i.mode != constants.LocalContainer {
		return nil
	}

	if err := i.ipt.Delete(i.appAckPacketIPTableContext, i.appPacketIPTableSection,
		"-m", "mark",
		"--mark", strconv.Itoa(i.fqc.GetMarkValue()),
		"-j", "ACCEPT"); err != nil {

		zap.L().Warn("Can not clear mark rule", zap.Error(err))
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

	// Clean Application Rules/Chains in Raw if needed
	if i.mode == constants.LocalContainer {
		i.cleanACLSection(i.appPacketIPTableContext, i.appPacketIPTableSection, i.appPacketIPTableSection, chainPrefix)
	}

	// Clean Application Rules/Chains
	i.cleanACLSection(i.appAckPacketIPTableContext, i.netPacketIPTableSection, i.appPacketIPTableSection, chainPrefix)

	return nil
}

func (i *Instance) cleanACLSection(context, netSection, appSection, chainPrefix string) {

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
func (i *Instance) addExclusionACLs(appChain, netChain string, ip string, exclusions []string) error {

	for _, e := range exclusions {

		if err := i.ipt.Insert(
			i.appAckPacketIPTableContext, appChain, 1,
			"-s", ip,
			"-d", e,
			"-j", "ACCEPT",
		); err != nil {
			return fmt.Errorf("Failed to add exclusion rule for table %s, chain %s, ip %s with %s", i.appAckPacketIPTableContext, appChain, e, err.Error())
		}

		if err := i.ipt.Insert(
			i.netPacketIPTableContext, netChain, 1,
			"-s", e,
			"-d", ip,
			"-p", "tcp", "!", "--tcp-option", strconv.Itoa(int(packet.TCPAuthenticationOption)),
			"-j", "ACCEPT",
		); err != nil {
			return fmt.Errorf("Failed to add exclusion rule for table %s, chain %s, ip %s with %s", i.appAckPacketIPTableContext, netChain, e, err.Error())
		}
	}

	return nil
}
