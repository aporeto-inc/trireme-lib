package iptablesutils

import (
	"fmt"
	"strconv"
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

type ipTableUtils struct {
}

//IptableUtils is a utility interface to programming IP Tables
type IptableUtils interface {
	AppChainPrefix() string
	NetChainPrefix() string
	DefaultCacheIP(ips []string) (string, error)
	FilterMarkedPackets(table, chain string, mark int, provider provider.IptablesProvider) error
	AddContainerChain(appChain string, netChain string, provider provider.IptablesProvider) error
	deleteChain(context, chain string, provider provider.IptablesProvider) error
	DeleteAllContainerChains(appChain, netChain string, provider provider.IptablesProvider) error
	ChainRules(appChain string, netChain string, ip string) [][]string
	AddChainRules(appChain string, netChain string, ip string, provider provider.IptablesProvider) error
	DeleteChainRules(appChain, netChain, ip string, provider provider.IptablesProvider) error
	trapRules(appChain string, netChain string, network string, appQueue string, netQueue string) [][]string
	AddPacketTrap(appChain string, netChain string, ip string, targetNetworks []string, appQueue string, netQueue string, provider provider.IptablesProvider) error
	DeletePacketTrap(appChain string, netChain string, ip string, targetNetworks []string, appQueue string, netQueue string, provider provider.IptablesProvider) error
	AddAppACLs(chain string, ip string, rules []policy.IPRule, provider provider.IptablesProvider) error
	DeleteAppACLs(chain string, ip string, rules []policy.IPRule, provider provider.IptablesProvider) error
	AddNetACLs(chain, ip string, rules []policy.IPRule, provider provider.IptablesProvider) error
	DeleteNetACLs(chain string, ip string, rules []policy.IPRule, provider provider.IptablesProvider) error
	CleanACLs(provider provider.IptablesProvider) error
	CleanACLSection(context, section, chainPrefix string, provider provider.IptablesProvider)
	AddAppSetRule(set string, ip string, provider provider.IptablesProvider) error
	DeleteAppSetRule(set string, ip string, provider provider.IptablesProvider) error
	AddNetSetRule(set string, ip string, provider provider.IptablesProvider) error
	DeleteNetSetRule(set string, ip string, provider provider.IptablesProvider) error
	CreateACLSets(set string, rules []policy.IPRule, ips provider.IpsetProvider) error
	DeleteSet(set string, ips provider.IpsetProvider) error
	CleanIPSets(ips provider.IpsetProvider) error
	TrapRulesSet(set string, networkQueues string, applicationQueues string) [][]string
}

// NewIptableUtils returns the IptableUtils implementer
func NewIptableUtils() IptableUtils {
	return &ipTableUtils{}
}

func (r *ipTableUtils) AppChainPrefix() string {
	return appChainPrefix
}

func (r *ipTableUtils) NetChainPrefix() string {
	return netChainPrefix
}

func (r *ipTableUtils) DefaultCacheIP(ips []string) (string, error) {
	if len(ips) == 0 || ips == nil {
		return "", fmt.Errorf("No IPs present")
	}
	return ips[0], nil
}

func (r *ipTableUtils) FilterMarkedPackets(table, chain string, mark int, provider provider.IptablesProvider) error {
	err := provider.Insert(table, chain, 1,
		"-m", "mark",
		"--mark", strconv.Itoa(mark),
		"-j", "ACCEPT")
	if err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesutils",
			"table":   table,
			"chain":   chain,
		}).Error("Failed to install default mark chain.")

	}
	return err
}

// AddContainerChain adds a chain for the specific container and redirects traffic there
// This simplifies significantly the management and makes the iptable rules more readable
// All rules related to a container are contained within the dedicated chain
func (r *ipTableUtils) AddContainerChain(appChain string, netChain string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package":  "iptablesutils",
		"appChain": appChain,
		"netChain": netChain,
	}).Info("Add a container chain")

	if err := provider.NewChain(appPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":                 "iptablesutils",
			"appChain":                appChain,
			"netChain":                netChain,
			"appPacketIPTableContext": appPacketIPTableContext,
			"error":                   err.Error(),
		}).Debug("Failed to create the container specific chain")

		return err
	}

	if err := provider.NewChain(appAckPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":                    "iptablesutils",
			"appChain":                   appChain,
			"netChain":                   netChain,
			"appAckPacketIPTableContext": appAckPacketIPTableContext,
			"error": err.Error(),
		}).Debug("Failed to create the container specific chain")

		return err
	}

	if err := provider.NewChain(netPacketIPTableContext, netChain); err != nil {
		log.WithFields(log.Fields{
			"package":                 "iptablesutils",
			"appChain":                appChain,
			"netChain":                netChain,
			"netPacketIPTableContext": netPacketIPTableContext,
			"error":                   err.Error(),
		}).Debug("Failed to create the container specific chain")

		return err
	}

	return nil
}

// delete removes all the rules in the provided chain and deletes the
// chain
func (r *ipTableUtils) deleteChain(context, chain string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
		"context": context,
		"chain":   chain,
	}).Info("Delete a chain")

	if err := provider.ClearChain(context, chain); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesutils",
			"chain":   chain,
			"error":   err.Error(),
		}).Debug("Failed to clear the container specific chain")

		return err
	}

	if err := provider.DeleteChain(context, chain); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesutils",
			"chain":   chain,
			"error":   err.Error(),
		}).Debug("Failed to delete the container specific chain")

		return err
	}

	return nil
}

// DeleteAllContainerChains removes all the container specific chains and basic rules
func (r *ipTableUtils) DeleteAllContainerChains(appChain, netChain string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package":  "iptablesutils",
		"appChain": appChain,
		"netChain": netChain,
	}).Info("Delete all container chains")

	if err := r.deleteChain(appPacketIPTableContext, appChain, provider); err != nil {
		log.WithFields(log.Fields{
			"package":                 "iptablesutils",
			"appChain":                appChain,
			"netChain":                netChain,
			"error":                   err.Error(),
			"appPacketIPTableContext": appPacketIPTableContext,
		}).Debug("Failed to clear and delete the appChains")

		//TODO: how do we deal with errors here
	}

	if err := r.deleteChain(appAckPacketIPTableContext, appChain, provider); err != nil {
		log.WithFields(log.Fields{
			"package":  "iptablesutils",
			"appChain": appChain,
			"netChain": netChain,
			"error":    err.Error(),
			"appAckPacketIPTableContext": appAckPacketIPTableContext,
		}).Debug("Failed to clear and delete the appChains")
	}

	if err := r.deleteChain(netPacketIPTableContext, netChain, provider); err != nil {
		log.WithFields(log.Fields{
			"package":                 "iptablesutils",
			"appChain":                appChain,
			"netChain":                netChain,
			"error":                   err.Error(),
			"netPacketIPTableContext": netPacketIPTableContext,
		}).Debug("Failed to clear and delete the netChain")
	}

	return nil
}

// ChainRules provides the list of rules that are used to send traffic to
// a particular chain
func (r *ipTableUtils) ChainRules(appChain string, netChain string, ip string) [][]string {

	ChainRules := [][]string{
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

	return ChainRules
}

// addChains rules implements all the iptable rules that redirect traffic to a chain
func (r *ipTableUtils) AddChainRules(appChain string, netChain string, ip string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package":  "iptablesutils",
		"appChain": appChain,
		"netChain": netChain,
		"ip":       ip,
	}).Info("Add chain rules")

	ChainRules := r.ChainRules(appChain, netChain, ip)
	for _, cr := range ChainRules {

		if err := provider.Append(cr[0], cr[1], cr[2:]...); err != nil {
			log.WithFields(log.Fields{
				"package":  "iptablesutils",
				"appChain": appChain,
				"netChain": netChain,
				"ip":       ip,
				"error":    err.Error(),
			}).Debug("Failed to add the rule that redirects to container chain for chain rules")
			return err
		}
	}

	return nil
}

//DeleteChainRules deletes the rules that send traffic to our chain
func (r *ipTableUtils) DeleteChainRules(appChain, netChain, ip string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package":  "iptablesutils",
		"appChain": appChain,
		"netChain": netChain,
		"ip":       ip,
	}).Info("Delete chain rules")

	ChainRules := r.ChainRules(appChain, netChain, ip)
	for _, cr := range ChainRules {

		if err := provider.Delete(cr[0], cr[1], cr[2:]...); err != nil {
			log.WithFields(log.Fields{
				"package":  "iptablesutils",
				"appChain": appChain,
				"netChain": netChain,
				"ip":       ip,
				"error":    err.Error(),
			}).Debug("Failed to delete the rule that redirects to container chain for chain rules")

			return err
		}
	}

	return nil
}

//trapRules provides the packet trap rules to add/delete
func (r *ipTableUtils) trapRules(appChain string, netChain string, network string, appQueue string, netQueue string) [][]string {

	TrapRules := [][]string{
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

	return TrapRules
}

// AddPacketTrap adds the necessary iptables rules to capture control packets to user space
func (r *ipTableUtils) AddPacketTrap(appChain string, netChain string, ip string, targetNetworks []string, appQueue string, netQueue string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package":  "iptablesutils",
		"appChain": appChain,
		"netChain": netChain,
		"ip":       ip,
	}).Info("Add Packet trap")

	for _, network := range targetNetworks {

		TrapRules := r.trapRules(appChain, netChain, network, appQueue, netQueue)
		for _, tr := range TrapRules {

			if err := provider.Append(tr[0], tr[1], tr[2:]...); err != nil {
				log.WithFields(log.Fields{
					"package":  "iptablesutils",
					"appChain": appChain,
					"netChain": netChain,
					"ip":       ip,
					"error":    err.Error(),
				}).Debug("Failed to add the rule that redirects to container chain for packet trap")
				return err
			}
		}
	}

	return nil
}

// DeletePacketTrap deletes the iptables rules that trap control  packets to user space
func (r *ipTableUtils) DeletePacketTrap(appChain string, netChain string, ip string, targetNetworks []string, appQueue string, netQueue string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package":  "iptablesutils",
		"appChain": appChain,
		"netChain": netChain,
		"ip":       ip,
	}).Info("Delete Packet trap")

	for _, network := range targetNetworks {

		TrapRules := r.trapRules(appChain, netChain, network, appQueue, netQueue)
		for _, tr := range TrapRules {

			if err := provider.Delete(tr[0], tr[1], tr[2:]...); err != nil {
				log.WithFields(log.Fields{
					"package":  "iptablesutils",
					"appChain": appChain,
					"netChain": netChain,
					"ip":       ip,
					"error":    err.Error(),
				}).Debug("Failed to delete the rule that redirects to container chain for packet trap")
				return err
			}
		}
	}

	return nil
}

// AddAppACLs adds a set of rules to the external services that are initiated
// by an application. The allow rules are inserted with highest priority.
func (r *ipTableUtils) AddAppACLs(chain string, ip string, rules []policy.IPRule, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
		"ip":      ip,
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
				"package":                 "iptablesutils",
				"netPacketIPTableContext": netPacketIPTableContext,
				"chain":                   chain,
				"error":                   err.Error(),
			}).Debug("Error when adding app acl rule")
			return err
		}

	}

	if err := provider.Append(
		appAckPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP"); err != nil {

		log.WithFields(log.Fields{
			"package":                 "iptablesutils",
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   chain,
			"error":                   err.Error(),
		}).Debug("Error when adding default app acl rule")

		return err
	}

	return nil
}

// DeleteAppACLs deletes the rules associated with traffic to external services
func (r *ipTableUtils) DeleteAppACLs(chain string, ip string, rules []policy.IPRule, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
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
				"package":                 "iptablesutils",
				"netPacketIPTableContext": netPacketIPTableContext,
				"chain":                   chain,
				"error":                   err.Error(),
			}).Debug("Error when removing ingress app acl rule")

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
			"package":                 "iptablesutils",
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   chain,
			"error":                   err.Error(),
		}).Debug("Error when removing default ingress app acl default rule")
	}

	return nil
}

// AddNetACLs adds iptables rules that manage traffic from external services. The
// explicit rules are added with the higest priority since they are direct allows.
func (r *ipTableUtils) AddNetACLs(chain, ip string, rules []policy.IPRule, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
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
				"package":                 "iptablesutils",
				"netPacketIPTableContext": netPacketIPTableContext,
				"chain":                   chain,
				"error":                   err.Error(),
			}).Debug("Error when adding a net acl rule")

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
			"package":                 "iptablesutils",
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   chain,
			"error":                   err.Error(),
		}).Debug("Error when adding default net acl rule")

		return err
	}

	return nil
}

// DeleteNetACLs removes the iptable rules that manage traffic from external services
func (r *ipTableUtils) DeleteNetACLs(chain string, ip string, rules []policy.IPRule, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
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
				"package":                 "iptablesutils",
				"netPacketIPTableContext": netPacketIPTableContext,
				"chain":                   chain,
				"error":                   err.Error(),
			}).Debug("Error when removing the egress net ACL rule")

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
			"package":                 "iptablesutils",
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   chain,
			"error":                   err.Error(),
		}).Debug("Error when removing the net ACL rule")
	}

	return nil
}

func (r *ipTableUtils) CleanACLs(provider provider.IptablesProvider) error {
	log.WithFields(log.Fields{
		"package": "iptablesutils",
	}).Info("Cleaning all IPTables")

	// Clean Application Rules/Chains
	r.CleanACLSection(appPacketIPTableContext, appPacketIPTableSection, chainPrefix, provider)

	// Clean Application Rules/Chains
	r.CleanACLSection(appAckPacketIPTableContext, appPacketIPTableSection, chainPrefix, provider)

	// Clean Application Rules/Chains
	r.CleanACLSection(appAckPacketIPTableContext, appPacketIPTableSection, chainPrefix, provider)

	// Clean Network Rules/Chains
	r.CleanACLSection(netPacketIPTableContext, netPacketIPTableSection, chainPrefix, provider)

	return nil
}
func (r *ipTableUtils) CleanACLSection(context, section, chainPrefix string, provider provider.IptablesProvider) {

	log.WithFields(log.Fields{
		"package":     "iptablesutils",
		"context":     context,
		"section":     section,
		"chainPrefix": chainPrefix,
	}).Info("Clean ACL section")

	if err := provider.ClearChain(context, section); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesutils",
			"context": context,
			"section": section,
			"error":   err.Error(),
		}).Debug("Can not clear the section in iptables.")
		return
	}

	rules, err := provider.ListChains(context)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesutils",
			"context": context,
			"section": section,
			"error":   err.Error(),
		}).Debug("No chain rules found in iptables")
		return
	}

	for _, rule := range rules {

		if strings.Contains(rule, chainPrefix) {
			provider.ClearChain(context, rule)
			provider.DeleteChain(context, rule)
		}
	}
}

// AddAppSetRule
func (r *ipTableUtils) AddAppSetRule(set string, ip string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
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
			"package":                    "iptablesutils",
			"appAckPacketIPTableContext": appAckPacketIPTableContext,
			"error": err.Error(),
		}).Debug("Error when adding app acl rule")
		return err

	}

	return nil
}

// DeleteAppSetRule
func (r *ipTableUtils) DeleteAppSetRule(set string, ip string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
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
			"package":                 "iptablesutils",
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   appPacketIPTableSection,
			"error":                   err.Error(),
		}).Debug("Error when removing ingress app acl rule")

	}

	return nil
}

// AddNetSetRule
func (r *ipTableUtils) AddNetSetRule(set string, ip string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
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
			"package":                 "iptablesutils",
			"netPacketIPTableContext": netPacketIPTableContext,
			"error":                   err.Error(),
		}).Debug("Error when adding app acl rule")
		return err
	}
	return nil
}

// DeleteNetSetRule
func (r *ipTableUtils) DeleteNetSetRule(set string, ip string, provider provider.IptablesProvider) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
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
			"package":                 "iptablesutils",
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   appPacketIPTableSection,
			"error":                   err.Error(),
		}).Debug("Error when removing ingress app acl rule")

	}

	return nil
}

func (r *ipTableUtils) TrapRulesSet(set string, networkQueues string, applicationQueues string) [][]string {

	TrapRules := [][]string{
		// Application Syn and Syn/Ack in RAW
		{
			appPacketIPTableContext, appPacketIPTableSection,
			"-m", "set", "--match-set", set, "dst",
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "NFQUEUE", "--queue-balance", applicationQueues,
		},

		// Application Matching Trireme SRC and DST. Established connections.
		{
			appAckPacketIPTableContext, appPacketIPTableSection,
			"-m", "set", "--match-set", set, "src",
			"-m", "set", "--match-set", set, "dst",
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "ACCEPT",
		},

		// Application Matching Trireme SRC and DST. SYN, SYNACK connections.
		{
			appAckPacketIPTableContext, appPacketIPTableSection,
			"-m", "set", "--match-set", set, "src",
			"-m", "set", "--match-set", set, "dst",
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", applicationQueues,
		},

		// Default Drop from Trireme to Network
		{
			appAckPacketIPTableContext, appPacketIPTableSection,
			"-m", "set", "--match-set", set, "src",
			"-j", "DROP",
		},

		// Network Matching Trireme SRC and DST.
		{
			netPacketIPTableContext, netPacketIPTableSection,
			"-m", "set", "--match-set", set, "src",
			"-m", "set", "--match-set", set, "dst",
			"-p", "tcp",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", networkQueues,
		},

		// Default Drop from Network to Trireme.
		{
			netPacketIPTableContext, netPacketIPTableSection,
			"-m", "set", "--match-set", set, "dst",
			"-j", "DROP",
		},
	}

	return TrapRules
}

func (r *ipTableUtils) CreateACLSets(set string, rules []policy.IPRule, ips provider.IpsetProvider) error {
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

func (r *ipTableUtils) DeleteSet(set string, ips provider.IpsetProvider) error {
	ipSet, err := ips.NewIPset(set, "hash:net,port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Couldn't create IPSet for Trireme: %s", err)
	}

	ipSet.Destroy()
	return nil
}

func (r *ipTableUtils) CleanIPSets(ips provider.IpsetProvider) error {
	return ips.DestroyAll()
}
