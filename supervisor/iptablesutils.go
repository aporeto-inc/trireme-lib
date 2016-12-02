package supervisor

import (
	"fmt"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/provider"
	"github.com/bvandewalle/go-ipset/ipset"
)

const (
	chainPrefix                = "TRIREME-"
	appPacketIPTableContext    = "raw"
	appAckPacketIPTableContext = "mangle"
	appPacketIPTableSection    = "PREROUTING"
	appChainPrefix             = chainPrefix + "App-"
	netPacketIPTableContext    = "mangle"
	netPacketIPTableSection    = "POSTROUTING"
	netChainPrefix             = chainPrefix + "Net-"
)

func defaultCacheIP(ips []string) (string, error) {
	if len(ips) == 0 || ips == nil {
		return "", fmt.Errorf("No IPs present")
	}
	return ips[0], nil
}

// addContainerChain adds a chain for the specific container and redirects traffic there
// This simplifies significantly the management and makes the iptable rules more readable
// All rules related to a container are contained within the dedicated chain
func addContainerChain(appChain string, netChain string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package":  "supervisor",
		"appChain": appChain,
		"netChain": netChain,
	}).Info("Add a container chain")

	if err := provider.NewChain(appPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"appChain":                appChain,
			"netChain":                netChain,
			"appPacketIPTableContext": appPacketIPTableContext,
			"error":                   err,
		}).Error("Failed to create the container specific chain")

		return err
	}

	if err := provider.NewChain(appAckPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":                    "supervisor",
			"appChain":                   appChain,
			"netChain":                   netChain,
			"appAckPacketIPTableContext": appAckPacketIPTableContext,
			"error": err,
		}).Error("Failed to create the container specific chain")

		return err
	}

	if err := provider.NewChain(netPacketIPTableContext, netChain); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"appChain":                appChain,
			"netChain":                netChain,
			"netPacketIPTableContext": netPacketIPTableContext,
			"error":                   err,
		}).Error("Failed to create the container specific chain")

		return err
	}

	return nil
}

// delete removes all the rules in the provided chain and deletes the
// chain
func deleteChain(context, chain string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "supervisor",
		"context": context,
		"chain":   chain,
	}).Info("Delete a chain")

	if err := provider.ClearChain(context, chain); err != nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
			"chain":   chain,
			"error":   err,
		}).Error("Failed to clear the container specific chain")

		return err
	}

	if err := provider.DeleteChain(context, chain); err != nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
			"chain":   chain,
			"error":   err,
		}).Error("Failed to delete the container specific chain")

		return err
	}

	return nil
}

// deleteAllContainerChains removes all the container specific chains and basic rules
func deleteAllContainerChains(appChain, netChain string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package":  "supervisor",
		"appChain": appChain,
		"netChain": netChain,
	}).Info("Delete all container chains")

	if err := deleteChain(appPacketIPTableContext, appChain, provider); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"appChain":                appChain,
			"netChain":                netChain,
			"error":                   err,
			"appPacketIPTableContext": appPacketIPTableContext,
		}).Error("Failed to clear and delete the appChains")

		//TODO: how do we deal with errors here
	}

	if err := deleteChain(appAckPacketIPTableContext, appChain, provider); err != nil {
		log.WithFields(log.Fields{
			"package":  "supervisor",
			"appChain": appChain,
			"netChain": netChain,
			"error":    err,
			"appAckPacketIPTableContext": appAckPacketIPTableContext,
		}).Error("Failed to clear and delete the appChains")
	}

	if err := deleteChain(netPacketIPTableContext, netChain, provider); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"appChain":                appChain,
			"netChain":                netChain,
			"error":                   err,
			"netPacketIPTableContext": netPacketIPTableContext,
		}).Error("Failed to clear and delete the netChain")
	}

	return nil
}

// chainRules provides the list of rules that are used to send traffic to
// a particular chain
func chainRules(appChain string, netChain string, ip string) [][]string {

	chainRules := [][]string{
		{
			appPacketIPTableContext,
			appPacketIPTableSection,
			"-s", ip,
			"-m", "comment", "--comment", "Container specific chain",
			"-j", appChain,
		},
		{
			appAckPacketIPTableContext,
			appPacketIPTableSection,
			"-s", ip,
			"-p", "tcp",
			"-m", "comment", "--comment", "Container specific chain",
			"-j", appChain,
		},
		{
			netPacketIPTableContext,
			netPacketIPTableSection,
			"-d", ip,
			"-m", "comment", "--comment", "Container specific chain",
			"-j", netChain,
		},
	}

	return chainRules
}

// addChains rules implements all the iptable rules that redirect traffic to a chain
func addChainRules(appChain string, netChain string, ip string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package":  "supervisor",
		"appChain": appChain,
		"netChain": netChain,
		"ip":       ip,
	}).Info("Add chain rules")

	chainRules := chainRules(appChain, netChain, ip)
	for _, cr := range chainRules {

		if err := provider.Append(cr[0], cr[1], cr[2:]...); err != nil {
			log.WithFields(log.Fields{
				"package":       "supervisor",
				"appChain":      appChain,
				"netChain":      netChain,
				"ip":            ip,
				"chainRules[0]": cr[0],
				"chainRules[1]": cr[1],
				"error":         err,
			}).Error("Failed to add the rule that redirects to container chain for chain rules")
			return err
		}
	}

	return nil
}

//deleteChainRules deletes the rules that send traffic to our chain
func deleteChainRules(appChain, netChain, ip string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package":  "supervisor",
		"appChain": appChain,
		"netChain": netChain,
		"ip":       ip,
	}).Info("Delete chain rules")

	chainRules := chainRules(appChain, netChain, ip)
	for _, cr := range chainRules {

		if err := provider.Delete(cr[0], cr[1], cr[2:]...); err != nil {
			log.WithFields(log.Fields{
				"package":       "supervisor",
				"appChain":      appChain,
				"netChain":      netChain,
				"ip":            ip,
				"chainRules[0]": cr[0],
				"chainRules[1]": cr[1],
				"error":         err,
			}).Error("Failed to delete the rule that redirects to container chain for chain rules")

			return err
		}
	}

	return nil
}

//RemotetrapRules exported
//provides rules for remote supervisor
func RemotetrapRules(appChain string, netChain string, network string, appQueue string, netQueue string) [][]string {
	trapRules := [][]string{
		// Application Syn and Syn/Ack
		{
			appPacketIPTableContext, appChain,
			//"-d", network,
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "NFQUEUE", "--queue-balance", appQueue,
		},

		// Application everything else
		{
			appAckPacketIPTableContext, appChain,
			//"-d", network,
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "ACCEPT",
		},

		// Application everything else
		{
			appAckPacketIPTableContext, appChain,
			//"-d", network,
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", appQueue,
		},

		// Network side rules
		{
			netPacketIPTableContext, netChain,
			//"-s", network,
			"-p", "tcp",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", netQueue,
		},
	}

	return trapRules
}

//trapRules provides the packet trap rules to add/delete
func trapRules(appChain string, netChain string, network string, appQueue string, netQueue string) [][]string {

	trapRules := [][]string{
		// Application Syn and Syn/Ack
		{
			appPacketIPTableContext, appChain,
			"-d", network,
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "NFQUEUE", "--queue-balance", appQueue,
		},

		// Application everything else
		{
			appAckPacketIPTableContext, appChain,
			"-d", network,
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "ACCEPT",
		},

		// Application everything else
		{
			appAckPacketIPTableContext, appChain,
			"-d", network,
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", appQueue,
		},

		// Network side rules
		{
			netPacketIPTableContext, netChain,
			"-s", network,
			"-p", "tcp",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", netQueue,
		},
	}

	return trapRules
}

// addPacketTrap adds the necessary iptables rules to capture control packets to user space
func addPacketTrap(appChain string, netChain string, ip string, targetNetworks []string, appQueue string, netQueue string, provider provider.IptablesProvider, remote bool) error {

	for _, network := range targetNetworks {
		var rules [][]string
		if remote {
			rules = RemotetrapRules(appChain, netChain, network, appQueue, netQueue)
		} else {
			rules = trapRules(appChain, netChain, network, appQueue, netQueue)
		}
		for _, tr := range rules {

			if err := provider.Append(tr[0], tr[1], tr[2:]...); err != nil {
				log.WithFields(log.Fields{
					"package":     "supervisor",
					"appChain":    appChain,
					"netChain":    netChain,
					"ip":          ip,
					"trapRule[0]": tr[0],
					"trapRule[1]": tr[1],
					"error":       err,
				}).Error("Failed to add the rule that redirects to container chain for packet trap")
				return err
			}
		}
	}

	return nil
}

// deletePacketTrap deletes the iptables rules that trap control  packets to user space
func deletePacketTrap(appChain string, netChain string, ip string, targetNetworks []string, appQueue string, netQueue string, provider provider.IptablesProvider, remote bool) error {

	log.WithFields(log.Fields{
		"package":  "supervisor",
		"appChain": appChain,
		"netChain": netChain,
		"ip":       ip,
	}).Info("Delete Packet trap")

	for _, network := range targetNetworks {
		var rules [][]string
		if remote {
			rules = RemotetrapRules(appChain, netChain, network, appQueue, netQueue)
		} else {
			rules = trapRules(appChain, netChain, network, appQueue, netQueue)
		}
		for _, tr := range rules {

			if err := provider.Delete(tr[0], tr[1], tr[2:]...); err != nil {
				log.WithFields(log.Fields{
					"package":     "supervisor",
					"appChain":    appChain,
					"netChain":    netChain,
					"ip":          ip,
					"trapRule[0]": tr[0],
					"trapRule[1]": tr[1],
					"error":       err,
				}).Error("Failed to delete the rule that redirects to container chain for packet trap")
				return err
			}
		}
	}

	return nil
}

// addAppACLs adds a set of rules to the external services that are initiated
// by an application. The allow rules are inserted with highest priority.
func addAppACLs(chain string, ip string, rules []policy.IPRule, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "supervisor",
		"ip":      ip,
		"rules":   rules,
		"chain":   chain,
	}).Info("Add App ACLs")

	for i := range rules {

		if err := provider.Append(
			appAckPacketIPTableContext, chain,
			"-p", rules[i].Protocol, "-m", "state", "--state", "NEW",
			"-d", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			log.WithFields(log.Fields{
				"package":                 "supervisor",
				"netPacketIPTableContext": netPacketIPTableContext,
				"chain":                   chain,
				"rule":                    rules[i],
				"error":                   err,
			}).Error("Error when adding app acl rule")
			return err
		}

	}

	if err := provider.Append(
		appAckPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP"); err != nil {

		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   chain,
			"error":                   err,
		}).Error("Error when adding default app acl rule")

		return err
	}

	return nil
}

// deleteAppACLs deletes the rules associated with traffic to external services
func deleteAppACLs(chain string, ip string, rules []policy.IPRule, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "supervisor",
		"ip":      ip,
		"rules":   rules,
		"chain":   chain,
	}).Info("Delete App ACLs")

	for i := range rules {
		if err := provider.Delete(
			appAckPacketIPTableContext, chain,
			"-p", rules[i].Protocol, "-m", "state", "--state", "NEW",
			"-d", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			log.WithFields(log.Fields{
				"package":                 "supervisor",
				"netPacketIPTableContext": netPacketIPTableContext,
				"chain":                   chain,
				"rule":                    rules[i],
				"error":                   err,
			}).Error("Error when removing ingress app acl rule")

			// TODO: how do we deal with errors ?
		}
	}

	if err := provider.Delete(
		appAckPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP",
	); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   chain,
			"error":                   err,
		}).Error("Error when removing default ingress app acl default rule")
	}

	return nil
}

// addNetACLs adds iptables rules that manage traffic from external services. The
// explicit rules are added with the higest priority since they are direct allows.
func addNetACLs(chain, ip string, rules []policy.IPRule, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "supervisor",
		"ip":      ip,
		"rules":   rules,
		"chain":   chain,
	}).Info("Add Net ACLs")

	for i := range rules {

		if err := provider.Append(
			netPacketIPTableContext, chain,
			"-p", rules[i].Protocol,
			"-s", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			log.WithFields(log.Fields{
				"package":                 "supervisor",
				"netPacketIPTableContext": netPacketIPTableContext,
				"chain":                   chain,
				"error":                   err,
				"rule":                    rules[i],
			}).Error("Error when adding a net acl rule")

			return err
		}

	}

	if err := provider.Append(
		netPacketIPTableContext, chain,
		"-s", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP",
	); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   chain,
			"error":                   err,
		}).Error("Error when adding default net acl rule")

		return err
	}

	return nil
}

// deleteNetACLs removes the iptable rules that manage traffic from external services
func deleteNetACLs(chain string, ip string, rules []policy.IPRule, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "supervisor",
		"ip":      ip,
		"rules":   rules,
		"chain":   chain,
	}).Info("Delete Net ACLs")

	for i := range rules {
		if err := provider.Delete(
			netPacketIPTableContext, chain,
			"-p", rules[i].Protocol,
			"-s", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			log.WithFields(log.Fields{
				"package":                 "supervisor",
				"netPacketIPTableContext": netPacketIPTableContext,
				"chain":                   chain,
				"rule":                    rules[i],
				"error":                   err,
			}).Error("Error when removing the egress net ACL rule")

			// TODO: how do we deal with the errors here
		}
	}

	if err := provider.Delete(
		netPacketIPTableContext, chain,
		"-s", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP",
	); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   chain,
			"error":                   err,
		}).Error("Error when removing the net ACL rule")
	}

	return nil
}

func cleanACLSection(context, section, chainPrefix string, provider provider.IptablesProvider) {

	log.WithFields(log.Fields{
		"package":     "supervisor",
		"context":     context,
		"section":     section,
		"chainPrefix": chainPrefix,
	}).Info("Clean ACL section")

	if err := provider.ClearChain(context, section); err != nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
			"context": context,
			"section": section,
			"error":   err,
		}).Error("Can not clear the section in iptables.")
		return
	}

	rules, err := provider.ListChains(context)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
			"context": context,
			"section": section,
			"error":   err,
		}).Error("No chain rules found in iptables")
		return
	}

	for _, rule := range rules {

		if strings.Contains(rule, chainPrefix) {
			provider.ClearChain(context, rule)
			provider.DeleteChain(context, rule)
		}
	}
}

// addAppSetRule
func addAppSetRule(set string, ip string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "supervisor",
		"ip":      ip,
		"set":     set,
	}).Info("Add App ACLs")

	if err := provider.Insert(
		appAckPacketIPTableContext, appPacketIPTableSection, 3,
		"-m", "state", "--state", "NEW",
		"-m", "set", "--match-set", set, "dst",
		"-s", ip,
		"-j", "ACCEPT",
	); err != nil {
		log.WithFields(log.Fields{
			"package":                    "supervisor",
			"appAckPacketIPTableContext": appAckPacketIPTableContext,
			"error": err,
		}).Error("Error when adding app acl rule")
		return err

	}

	return nil
}

// deleteAppSetRule
func deleteAppSetRule(set string, ip string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "supervisor",
		"ip":      ip,
	}).Info("Delete App ACLs")

	if err := provider.Delete(
		appAckPacketIPTableContext, appPacketIPTableSection,
		"-m", "state", "--state", "NEW",
		"-m", "set", "--match-set", set, "dst",
		"-s", ip,
		"-j", "ACCEPT",
	); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   appPacketIPTableSection,
			"error":                   err,
		}).Error("Error when removing ingress app acl rule")

	}

	return nil
}

// addNetSetRule
func addNetSetRule(set string, ip string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "supervisor",
		"ip":      ip,
		"set":     set,
	}).Info("Add App ACLs")

	if err := provider.Insert(
		netPacketIPTableContext, netPacketIPTableSection, 2,
		"-m", "state", "--state", "NEW",
		"-m", "set", "--match-set", set, "src",
		"-d", ip,
		"-j", "ACCEPT",
	); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"netPacketIPTableContext": netPacketIPTableContext,
			"error":                   err,
		}).Error("Error when adding app acl rule")
		return err
	}
	return nil
}

// deleteNetSetRule
func deleteNetSetRule(set string, ip string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "supervisor",
		"ip":      ip,
	}).Info("Delete App ACLs")

	if err := provider.Delete(
		netPacketIPTableContext, netPacketIPTableSection,
		"-m", "state", "--state", "NEW",
		"-m", "set", "--match-set", set, "src",
		"-d", ip,
		"-j", "ACCEPT",
	); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   appPacketIPTableSection,
			"error":                   err,
		}).Error("Error when removing ingress app acl rule")

	}

	return nil
}

func createACLSets(set string, rules []policy.IPRule, ips provider.IpsetProvider) error {
	appSet, err := ips.NewIPset(set, "hash:net,port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Couldn't create IPSet for Trireme: %s", err)
	}

	for _, rule := range rules {
		if err := appSet.Add(rule.Address+","+rule.Port, 0); err != nil {
			return fmt.Errorf("Couldn't create IPSet for Trireme: %s", err)
		}
	}
	return nil
}

func deleteSet(set string, ips provider.IpsetProvider) error {
	ipSet, err := ips.NewIPset(set, "hash:net,port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Couldn't create IPSet for Trireme: %s", err)
	}

	ipSet.Destroy()
	return nil
}

func cleanIPSets(ips provider.IpsetProvider) error {
	return ips.DestroyAll()
}
