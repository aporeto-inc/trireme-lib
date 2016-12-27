package iptablesctrl

import (
	"fmt"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/policy"
)

// chainRules provides the list of rules that are used to send traffic to
// a particular chain
func (i *Instance) chainRules(appChain string, netChain string, ip string) [][]string {

	return [][]string{
		{
			i.appPacketIPTableContext,
			i.appPacketIPTableSection,
			"-s", ip,
			"-m", "comment", "--comment", "Container specific chain",
			"-j", appChain,
		},
		{
			i.appAckPacketIPTableContext,
			i.appPacketIPTableSection,
			"-s", ip,
			"-p", "tcp",
			"-m", "comment", "--comment", "Container specific chain",
			"-j", appChain,
		},
		{
			i.netPacketIPTableContext,
			i.netPacketIPTableSection,
			"-d", ip,
			"-m", "comment", "--comment", "Container specific chain",
			"-j", netChain,
		},
	}
}

//trapRules provides the packet trap rules to add/delete
func (i *Instance) trapRules(appChain string, netChain string, network string, appQueue string, netQueue string) [][]string {

	return [][]string{
		// Application Syn and Syn/Ack
		{
			i.appPacketIPTableContext, appChain,
			"-d", network,
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "NFQUEUE", "--queue-balance", appQueue,
		},

		// Application everything else
		{
			i.appAckPacketIPTableContext, appChain,
			"-d", network,
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", appQueue,
		},

		// Network side rules
		{
			i.netPacketIPTableContext, netChain,
			"-s", network,
			"-p", "tcp",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", netQueue,
		},
	}
}

// exclusionChainRules provides the list of rules that are used to send traffic to
// a particular chain
func (i *Instance) exclusionChainRules(ip string) [][]string {

	return [][]string{
		{
			i.appPacketIPTableContext,
			i.appPacketIPTableSection,
			"-d", ip,
			"-m", "comment", "--comment", "Trireme excluded IP",
			"-j", "ACCEPT",
		},
		{
			i.appAckPacketIPTableContext,
			i.appPacketIPTableSection,
			"-d", ip,
			"-p", "tcp",
			"-m", "comment", "--comment", "Trireme excluded IP",
			"-j", "ACCEPT",
		},
		{
			i.netPacketIPTableContext,
			i.netPacketIPTableSection,
			"-s", ip,
			"-m", "comment", "--comment", "Trireme excluded IP",
			"-j", "ACCEPT",
		},
	}

}

// addContainerChain adds a chain for the specific container and redirects traffic there
// This simplifies significantly the management and makes the iptable rules more readable
// All rules related to a container are contained within the dedicated chain
func (i *Instance) addContainerChain(appChain string, netChain string) error {

	if err := i.ipt.NewChain(i.appPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":                   "iptablesctrl",
			"appChain":                  appChain,
			"netChain":                  netChain,
			"i.appPacketIPTableContext": i.appPacketIPTableContext,
			"error":                     err.Error(),
		}).Debug("Failed to create the container specific chain")
		return err
	}

	if err := i.ipt.NewChain(i.appAckPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":                      "iptablesctrl",
			"appChain":                     appChain,
			"netChain":                     netChain,
			"i.appAckPacketIPTableContext": i.appAckPacketIPTableContext,
			"error": err.Error(),
		}).Debug("Failed to create the container specific chain")

		return err
	}

	if err := i.ipt.NewChain(i.netPacketIPTableContext, netChain); err != nil {
		log.WithFields(log.Fields{
			"package":                   "iptablesctrl",
			"appChain":                  appChain,
			"netChain":                  netChain,
			"i.netPacketIPTableContext": i.netPacketIPTableContext,
			"error":                     err.Error(),
		}).Debug("Failed to create the container specific chain")

		return err
	}

	return nil
}

func (i *Instance) processRulesFromList(rulelist [][]string, methodType string) error {
	for _, cr := range rulelist {
		switch methodType {
		case "Append":
			if err := i.ipt.Append(cr[0], cr[1], cr[2:]...); err != nil {
				log.WithFields(log.Fields{
					"package": "iptablesctrl",
					"method":  "Append",
					"table":   cr[0],
					"chain":   cr[1],
					"error":   err.Error(),
				}).Debug("Failed to append rule")
				return err
			}
		case "Insert":
			if err := i.ipt.Insert(cr[0], cr[1], 1, cr[2:]...); err != nil {
				log.WithFields(log.Fields{
					"package": "iptablesctrl",
					"method":  "Insert",
					"table":   cr[0],
					"chain":   cr[1],
				}).Debug("Failed insert rule")
				return err
			}
		case "Delete":
			if err := i.ipt.Delete(cr[0], cr[1], cr[2:]...); err != nil {
				log.WithFields(log.Fields{
					"package": "iptablesctrl",
					"method":  "Insert",
					"table":   cr[0],
					"chain":   cr[1],
				}).Debug("Failed to delete rule")
				return err
			}
		default:
			return fmt.Errorf("Invalid method type")
		}
	}
	return nil
}

// addChainrules implements all the iptable rules that redirect traffic to a chain
func (i *Instance) addChainRules(appChain string, netChain string, ip string) error {

	return i.processRulesFromList(i.chainRules(appChain, netChain, ip), "Append")

}

// addPacketTrap adds the necessary iptables rules to capture control packets to user space
func (i *Instance) addPacketTrap(appChain string, netChain string, ip string) error {

	for _, network := range i.targetNetworks {

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

		switch rule.Action {
		case policy.Accept:
			if err := i.ipt.Append(
				i.appAckPacketIPTableContext, chain,
				"-p", rule.Protocol, "-m", "state", "--state", "NEW",
				"-d", rule.Address,
				"--dport", rule.Port,
				"-j", "ACCEPT",
			); err != nil {
				log.WithFields(log.Fields{
					"package":                   "iptablesctrl",
					"i.netPacketIPTableContext": i.netPacketIPTableContext,
					"chain":                     chain,
					"error":                     err.Error(),
				}).Debug("Error when adding app acl rule")
				return err
			}
		case policy.Reject:
			if err := i.ipt.Insert(
				i.appAckPacketIPTableContext, chain, 1,
				"-p", rule.Protocol, "-m", "state", "--state", "NEW",
				"-d", rule.Address,
				"--dport", rule.Port,
				"-j", "DROP",
			); err != nil {
				log.WithFields(log.Fields{
					"package":                   "iptablesctrl",
					"i.netPacketIPTableContext": i.netPacketIPTableContext,
					"chain":                     chain,
					"error":                     err.Error(),
				}).Debug("Error when adding app acl rule")
				return err
			}
		default:
			continue
		}
	}

	if err := i.ipt.Append(
		i.appAckPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP"); err != nil {

		log.WithFields(log.Fields{
			"package":                   "iptablesctrl",
			"i.netPacketIPTableContext": i.netPacketIPTableContext,
			"chain":                     chain,
			"error":                     err.Error(),
		}).Debug("Error when adding default app acl rule")
		return err
	}

	return nil
}

// addNetACLs adds iptables rules that manage traffic from external services. The
// explicit rules are added with the higest priority since they are direct allows.
func (i *Instance) addNetACLs(chain, ip string, rules *policy.IPRuleList) error {

	for _, rule := range rules.Rules {

		switch rule.Action {
		case policy.Accept:
			if err := i.ipt.Append(
				i.netPacketIPTableContext, chain,
				"-p", rule.Protocol,
				"-s", rule.Address,
				"--dport", rule.Port,
				"-j", "ACCEPT",
			); err != nil {
				log.WithFields(log.Fields{
					"package":                   "iptablesctrl",
					"i.netPacketIPTableContext": i.netPacketIPTableContext,
					"chain":                     chain,
					"error":                     err.Error(),
				}).Debug("Error when adding a net acl rule")

				return err
			}
		case policy.Reject:
			if err := i.ipt.Insert(
				i.netPacketIPTableContext, chain, 1,
				"-p", rule.Protocol,
				"-s", rule.Address,
				"--dport", rule.Port,
				"-j", "DROP",
			); err != nil {
				log.WithFields(log.Fields{
					"package":                   "iptablesctrl",
					"i.netPacketIPTableContext": i.netPacketIPTableContext,
					"chain":                     chain,
					"error":                     err.Error(),
				}).Debug("Error when adding a net acl rule")

				return err
			}
		default:
			continue
		}
	}

	if err := i.ipt.Append(
		i.netPacketIPTableContext, chain,
		"-s", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP",
	); err != nil {
		log.WithFields(log.Fields{
			"package":                   "iptablesctrl",
			"i.netPacketIPTableContext": i.netPacketIPTableContext,
			"chain":                     chain,
			"error":                     err.Error(),
		}).Debug("Error when adding default net acl rule")

		return err
	}

	return nil
}

// deleteChainRules deletes the rules that send traffic to our chain
func (i *Instance) deleteChainRules(appChain, netChain, ip string) error {

	return i.processRulesFromList(i.chainRules(appChain, netChain, ip), "Delete")

}

// deleteAllContainerChains removes all the container specific chains and basic rules
func (i *Instance) deleteAllContainerChains(appChain, netChain string) error {

	if err := i.ipt.ClearChain(i.appPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"chain":   appChain,
			"error":   err.Error(),
		}).Debug("Failed to clear the container specific chain")
	}

	if err := i.ipt.DeleteChain(i.appPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":                   "iptablesctrl",
			"appChain":                  appChain,
			"netChain":                  netChain,
			"error":                     err.Error(),
			"i.appPacketIPTableContext": i.appPacketIPTableContext,
		}).Debug("Failed to clear and delete the appChains")

		//TODO: how do we deal with errors here
	}

	if err := i.ipt.ClearChain(i.appAckPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"chain":   appChain,
			"error":   err.Error(),
		}).Debug("Failed to clear the container specific chain")
	}

	if err := i.ipt.DeleteChain(i.appAckPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":  "iptablesctrl",
			"appChain": appChain,
			"netChain": netChain,
			"error":    err.Error(),
			"i.appAckPacketIPTableContext": i.appAckPacketIPTableContext,
		}).Debug("Failed to clear and delete the appChains")
	}

	if err := i.ipt.ClearChain(i.netPacketIPTableContext, netChain); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"chain":   netChain,
			"error":   err.Error(),
		}).Debug("Failed to clear the container specific chain")
	}

	if err := i.ipt.DeleteChain(i.netPacketIPTableContext, netChain); err != nil {
		log.WithFields(log.Fields{
			"package":                   "iptablesctrl",
			"appChain":                  appChain,
			"netChain":                  netChain,
			"error":                     err.Error(),
			"i.netPacketIPTableContext": i.netPacketIPTableContext,
		}).Debug("Failed to clear and delete the netChain")
	}

	return nil
}

func (i *Instance) acceptMarkedPackets() error {
	table := i.appAckPacketIPTableContext
	chain := i.appPacketIPTableSection
	err := i.ipt.Insert(table, chain, 1,
		"-m", "mark",
		"--mark", strconv.Itoa(i.mark),
		"-j", "ACCEPT")
	if err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"table":   table,
			"chain":   chain,
		}).Debug("Failed to install default mark chain.")
	}
	return err
}

func (i *Instance) removeMarkRule() error {

	i.ipt.Delete(i.appAckPacketIPTableContext, i.appPacketIPTableSection,
		"-m", "mark",
		"--mark", strconv.Itoa(i.mark),
		"-j", "ACCEPT")
	return nil
}

func (i *Instance) cleanACLs() error {
	log.WithFields(log.Fields{
		"package": "iptablesctrl",
	}).Debug("Cleaning all IPTables")

	// Clean the mark rule
	i.removeMarkRule()

	// Clean Application Rules/Chains
	i.cleanACLSection(i.appPacketIPTableContext, i.appPacketIPTableSection, chainPrefix)

	// Clean Application Rules/Chains
	i.cleanACLSection(i.appAckPacketIPTableContext, i.appPacketIPTableSection, chainPrefix)

	// Clean Network Rules/Chains
	i.cleanACLSection(i.netPacketIPTableContext, i.netPacketIPTableSection, chainPrefix)

	return nil
}

func (i *Instance) cleanACLSection(context, section, chainPrefix string) {

	if err := i.ipt.ClearChain(context, section); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"context": context,
			"section": section,
			"error":   err.Error(),
		}).Debug("Can not clear the section in iptables.")
	}

	rules, err := i.ipt.ListChains(context)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesctrl",
			"context": context,
			"section": section,
			"error":   err.Error(),
		}).Debug("No chain rules found in iptables")
	}

	for _, rule := range rules {

		if strings.Contains(rule, chainPrefix) {
			i.ipt.ClearChain(context, rule)
			i.ipt.DeleteChain(context, rule)
		}
	}
}

// addExclusionChainRules adds exclusion chain rules
func (i *Instance) addExclusionChainRules(ip string) error {

	return i.processRulesFromList(i.exclusionChainRules(ip), "Insert")

}

// deleteExclusionChainRules removes exclusion chain rules
func (i *Instance) deleteExclusionChainRules(ip string) error {

	return i.processRulesFromList(i.exclusionChainRules(ip), "Delete")

}
