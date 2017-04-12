package iptablesctrl

import (
	"fmt"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/policy"
)

func (i *Instance) cgroupChainRules(appChain string, netChain string, mark string, port string) [][]string {

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
func (i *Instance) trapRules(appChain string, netChain string, network string, appQueue string, netQueue string) [][]string {

	rules := [][]string{}

	if i.mode == constants.LocalContainer {
		rules = append(rules, []string{
			i.appPacketIPTableContext, appChain,
			"-d", network,
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "NFQUEUE", "--queue-balance", appQueue,
		})

		rules = append(rules, []string{
			i.appAckPacketIPTableContext, appChain,
			"-d", network,
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", appQueue,
		})

		// Capture the first ack packet
		rules = append(rules, []string{
			i.netPacketIPTableContext, netChain,
			"-s", network,
			"-p", "tcp",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", netQueue,
		})

	} else {
		rules = append(rules, []string{
			i.appAckPacketIPTableContext, appChain,
			"-d", network,
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", appQueue,
		})

		rules = append(rules, []string{
			i.appAckPacketIPTableContext, appChain,
			"-d", network,
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", appQueue,
		})

		// Capture Syn Packets
		rules = append(rules, []string{
			i.netPacketIPTableContext, netChain,
			"-s", network,
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN",
			"-j", "NFQUEUE", "--queue-balance", netQueue,
		})

		rules = append(rules, []string{
			i.netPacketIPTableContext, netChain,
			"-s", network,
			"-p", "tcp", "--tcp-flags", "SYN,ACK,PSH", "ACK",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", netQueue,
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
		return fmt.Errorf("Failed to add  netchain %s of context %s : %s", netChain, i.netPacketIPTableContext, err.Error())
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
				log.WithFields(log.Fields{
					"package": "iptablesctrl",
					"table":   cr[0],
					"chain":   cr[1],
					"error":   err.Error(),
				}).Warn("Failed to delete rule from chain")
			}
		default:
			return fmt.Errorf("Invalid method type")
		}
	}
	return nil
}

// addChainrules implements all the iptable rules that redirect traffic to a chain
func (i *Instance) addChainRules(appChain string, netChain string, ip string, port string, mark string) error {

	if i.mode == constants.LocalServer {
		return i.processRulesFromList(i.cgroupChainRules(appChain, netChain, mark, port), "Append")
	}

	return i.processRulesFromList(i.chainRules(appChain, netChain, ip), "Append")

}

// addPacketTrap adds the necessary iptables rules to capture control packets to user space
func (i *Instance) addPacketTrap(appChain string, netChain string, ip string, networks []string) error {

	for _, network := range networks {

		err := i.processRulesFromList(i.trapRules(appChain, netChain, network, i.applicationQueues, i.networkQueues), "Append")
		if err != nil {
			return err
		}
	}

	return nil
}

// addAppACLs adds a set of rules to the external services that are initiated
// by an application. The allow rules are inserted with highest priority.
func (i *Instance) addAppACLs(chain string, ip string, rules *policy.IPRuleList) error {

	for _, rule := range rules.Rules {
		if rule.Protocol == "UDP" || rule.Protocol == "TCP" {
			switch rule.Action {
			case policy.Accept:
				if err := i.ipt.Append(
					i.appAckPacketIPTableContext, chain,
					"-p", rule.Protocol, "-m", "state", "--state", "NEW",
					"-d", rule.Address,
					"--dport", rule.Port,
					"-j", "ACCEPT",
				); err != nil {
					return fmt.Errorf("Failed to add acl rule for table %s, chain %s, with  %s", i.appAckPacketIPTableContext, chain, err.Error())
				}
			case policy.Reject:
				if err := i.ipt.Insert(
					i.appAckPacketIPTableContext, chain, 1,
					"-p", rule.Protocol, "-m", "state", "--state", "NEW",
					"-d", rule.Address,
					"--dport", rule.Port,
					"-j", "DROP",
				); err != nil {
					return fmt.Errorf("Failed to add acl rule for table %s, chain %s, with  %s", i.appAckPacketIPTableContext, chain, err.Error())
				}
			default:
				continue
			}
		} else {
			switch rule.Action {
			case policy.Accept:
				if err := i.ipt.Append(
					i.appAckPacketIPTableContext, chain,
					"-p", rule.Protocol,
					"-d", rule.Address,
					"-j", "ACCEPT",
				); err != nil {
					return fmt.Errorf("Failed to add acl rule for table %s, chain %s, with  %s", i.appAckPacketIPTableContext, chain, err.Error())
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
func (i *Instance) addNetACLs(chain, ip string, rules *policy.IPRuleList) error {

	for _, rule := range rules.Rules {

		if rule.Protocol == "UDP" || rule.Protocol == "TCP" {
			switch rule.Action {
			case policy.Accept:
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
			default:
				continue
			}
		} else {
			switch rule.Action {
			case policy.Accept:
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
func (i *Instance) deleteChainRules(appChain, netChain, ip string, port string, mark string) error {

	if i.mode == constants.LocalServer {
		return i.processRulesFromList(i.cgroupChainRules(appChain, netChain, mark, port), "Delete")
	}

	return i.processRulesFromList(i.chainRules(appChain, netChain, ip), "Delete")
}

// deleteAllContainerChains removes all the container specific chains and basic rules
func (i *Instance) deleteAllContainerChains(appChain, netChain string) error {

	if err := i.ipt.ClearChain(i.appPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"chain":   appChain,
			"error":   err.Error(),
			"context": i.appPacketIPTableContext,
		}).Warn("Failed to clear the container specific chain")
	}

	if err := i.ipt.DeleteChain(i.appPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":                   "iptablesctrl",
			"appChain":                  appChain,
			"netChain":                  netChain,
			"error":                     err.Error(),
			"i.appPacketIPTableContext": i.appPacketIPTableContext,
		}).Warn("Failed to clear and delete the appChains")
	}

	if err := i.ipt.ClearChain(i.appAckPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"chain":   appChain,
			"error":   err.Error(),
			"context": i.appAckPacketIPTableContext,
		}).Warn("Failed to clear the container specific chain")
	}

	if err := i.ipt.DeleteChain(i.appAckPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":  "iptablesctrl",
			"appChain": appChain,
			"netChain": netChain,
			"error":    err.Error(),
			"context":  i.appAckPacketIPTableContext,
		}).Warn("Failed to clear and delete the appChains")
	}

	if err := i.ipt.ClearChain(i.netPacketIPTableContext, netChain); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"chain":   netChain,
			"error":   err.Error(),
			"context": i.netPacketIPTableContext,
		}).Warn("Failed to clear the container specific chain")
	}

	if err := i.ipt.DeleteChain(i.netPacketIPTableContext, netChain); err != nil {
		log.WithFields(log.Fields{
			"package":  "iptablesctrl",
			"appChain": appChain,
			"netChain": netChain,
			"error":    err.Error(),
			"context":  i.netPacketIPTableContext,
		}).Warn("Failed to clear and delete the netChain")
	}

	return nil
}

// CaptureSYNACKPackets install rules to capture all SynAck packets
func (i *Instance) CaptureSYNACKPackets() error {

	err := i.ipt.Insert(
		i.appAckPacketIPTableContext,
		i.appPacketIPTableSection, 1,
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "NFQUEUE", "--queue-bypass", "--queue-balance", i.applicationQueues)

	if err != nil {
		return fmt.Errorf("Failed to add capture SynAck rule for table %s, chain %s, with error: %s", i.appAckPacketIPTableContext, i.appPacketIPTableSection, err.Error())
	}

	err = i.ipt.Insert(
		i.netPacketIPTableContext,
		i.netPacketIPTableSection, 1,
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "NFQUEUE", "--queue-bypass", "--queue-balance", i.networkQueues)

	if err != nil {
		return fmt.Errorf("Failed to add capture SynAck rule for table %s, chain %s, with error: %s", i.netPacketIPTableContext, i.netPacketIPTableSection, err.Error())
	}

	return nil
}

// CleanCaptureSynAckPackets cleans the capture rules for SynAck packets
func (i *Instance) CleanCaptureSynAckPackets() error {

	if err := i.ipt.Delete(
		i.appAckPacketIPTableContext,
		i.appPacketIPTableSection,
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "NFQUEUE", "--queue-bypass", "--queue-balance", i.applicationQueues); err != nil {

		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"error":   err.Error(),
		}).Warn("Can not clear the SynAck packet capcture app chain.")
	}

	if err := i.ipt.Delete(
		i.netPacketIPTableContext,
		i.netPacketIPTableSection,
		"-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-j", "NFQUEUE", "--queue-bypass", "--queue-balance", i.networkQueues); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"error":   err.Error(),
		}).Warn("Can not clear the SynAck packet capcture net chain.")
	}

	return nil
}

// CleanAllSynAckPacketCaptures cleans the capture rules for SynAck packets irrespective of NFQUEUE
func (i *Instance) CleanAllSynAckPacketCaptures() error {

	if err := i.ipt.ClearChain(i.appAckPacketIPTableContext, i.appPacketIPTableContext); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"error":   err.Error(),
		}).Warn("Can not clear the SynAck packet capcture app chain.")
	}

	if err := i.ipt.ClearChain(i.netPacketIPTableContext, i.netPacketIPTableSection); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"error":   err.Error(),
		}).Warn("Can not clear the SynAck packet capcture net chain.")
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
		"--mark", strconv.Itoa(i.mark),
		"-j", "ACCEPT")

}

func (i *Instance) removeMarkRule() error {

	if i.mode != constants.LocalContainer {
		return nil
	}

	if err := i.ipt.Delete(i.appAckPacketIPTableContext, i.appPacketIPTableSection,
		"-m", "mark",
		"--mark", strconv.Itoa(i.mark),
		"-j", "ACCEPT"); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"error":   err.Error(),
		}).Warn("Can not clear Mark rule ")
	}

	return nil
}

func (i *Instance) cleanACLs() error {

	// Clean the mark rule
	if err := i.removeMarkRule(); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"error":   err.Error(),
		}).Warn("Can not clear the mark rules.")
	}

	if i.mode == constants.LocalServer {
		if err := i.CleanCaptureSynAckPackets(); err != nil {
			log.WithFields(log.Fields{
				"package": "iptablesctrl",
				"error":   err.Error(),
			}).Warn("Can not clear the SynAck ACLs.")
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
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"context": context,
			"section": appSection,
			"error":   err.Error(),
		}).Warn("Can not clear the section in iptables.")
	}

	if err := i.ipt.ClearChain(context, netSection); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"context": context,
			"section": netSection,
			"error":   err.Error(),
		}).Warn("Can not clear the section in iptables.")
	}

	rules, err := i.ipt.ListChains(context)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"context": context,
			"error":   err.Error(),
		}).Warn("Can not read the iptables chains.")
	}

	for _, rule := range rules {

		if strings.Contains(rule, chainPrefix) {

			if err := i.ipt.ClearChain(context, rule); err != nil {
				log.WithFields(log.Fields{
					"package":      "iptablesctrl",
					"context":      context,
					"chain prefix": rule,
					"error":        err.Error(),
				}).Warn("Can not clear the chain.")
			}

			if err := i.ipt.DeleteChain(context, rule); err != nil {
				log.WithFields(log.Fields{
					"package":      "iptablesctrl",
					"context":      context,
					"chain prefix": rule,
					"error":        err.Error(),
				}).Warn("Can not delete the chain.")
			}
		}
	}
}

// addExclusionACLs adds the set of IP addresses that must be excluded
func (i *Instance) addExclusionACLs(appchain, netchain string, ip string, exclusions []string) error {

	for _, e := range exclusions {
		if err := i.ipt.Insert(
			i.appAckPacketIPTableContext, appchain, 1,
			"-s", ip,
			"-d", e,
			"-j", "ACCEPT",
		); err != nil {
			return fmt.Errorf("Failed to add exclusion rule for table %s, chain %s, ip %s with  %s", i.appAckPacketIPTableContext, appchain, e, err.Error())
		}

		if err := i.ipt.Insert(
			i.netPacketIPTableContext, netchain, 1,
			"-s", e,
			"-d", ip,
			"-j", "ACCEPT",
		); err != nil {
			return fmt.Errorf("Failed to add exclusion rule for table %s, chain %s, ip %s with  %s", i.appAckPacketIPTableContext, netchain, e, err.Error())
		}
	}

	return nil
}
