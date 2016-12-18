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
	ipt   provider.IptablesProvider
	ips   provider.IpsetProvider
	ipset provider.Ipset
}

//IptableCommon is a utility interface for programming IP Tables and IP S
type IptableCommon interface {
	AppChainPrefix(contextID string, index int) string
	NetChainPrefix(contextID string, index int) string
	DefaultCacheIP(ips []string) (string, error)
	chainRules(appChain string, netChain string, ip string) [][]string
	trapRules(appChain string, netChain string, network string, appQueue string, netQueue string) [][]string
	CleanACLs() error
}

//IptableProviderUtils is a utility interface for programming IP Tables
type IptableProviderUtils interface {
	FilterMarkedPackets(mark int) error
	AddContainerChain(appChain string, netChain string) error
	deleteChain(context, chain string) error
	DeleteAllContainerChains(appChain, netChain string) error
	AddChainRules(appChain string, netChain string, ip string) error
	DeleteChainRules(appChain, netChain, ip string) error
	AddPacketTrap(appChain string, netChain string, ip string, targetNetworks []string, appQueue string, netQueue string) error
	AddAppACLs(chain string, ip string, rules []policy.IPRule) error
	AddNetACLs(chain, ip string, rules []policy.IPRule) error
	cleanACLSection(context, section, chainPrefix string)
	exclusionChainRules(ip string) [][]string
	AddExclusionChainRules(ip string) error
	DeleteExclusionChainRules(ip string) error
}

//IpsetProviderUtils is a utility interface for programming IP Sets
type IpsetProviderUtils interface {
	SetupIpset(name string, ips []string) error
	AddIpsetOption(ip string) error
	DeleteIpsetOption(ip string) error
	AddAppSetRule(set string, ip string) error
	DeleteAppSetRule(set string, ip string) error
	AddNetSetRule(set string, ip string) error
	DeleteNetSetRule(set string, ip string) error
	SetupTrapRules(set string, networkQueues string, applicationQueues string) error
	CreateACLSets(set string, rules []policy.IPRule) error
	DeleteSet(set string) error
	CleanIPSets() error
}

//IptableUtils is an interface
type IptableUtils interface {
	IptableCommon
	IptableProviderUtils
}

// IpsetUtils is an interface
type IpsetUtils interface {
	IptableCommon
	IpsetProviderUtils
}

// NewIptableUtils returns the IptableUtils implementer
func NewIptableUtils(p provider.IptablesProvider) IptableUtils {
	return &ipTableUtils{
		ipt: p,
	}
}

// NewIpsetUtils returns the IptableUtils implementer
func NewIpsetUtils(p provider.IptablesProvider, s provider.IpsetProvider) (IpsetUtils, error) {
	return &ipTableUtils{
		ipt: p,
		ips: s,
	}, nil
}

func (r *ipTableUtils) AppChainPrefix(contextID string, index int) string {
	return appChainPrefix + contextID + "-" + strconv.Itoa(index)
}

func (r *ipTableUtils) NetChainPrefix(contextID string, index int) string {
	return netChainPrefix + contextID + "-" + strconv.Itoa(index)
}

func (r *ipTableUtils) DefaultCacheIP(ips []string) (string, error) {
	if len(ips) == 0 || ips == nil {
		return "", fmt.Errorf("No IPs present")
	}
	return ips[0], nil
}

// ChainRules provides the list of rules that are used to send traffic to
// a particular chain
func (r *ipTableUtils) chainRules(appChain string, netChain string, ip string) [][]string {

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

func (r *ipTableUtils) CleanACLs() error {
	log.WithFields(log.Fields{
		"package": "iptablesutils",
	}).Debug("Cleaning all IPTables")

	// Clean Application Rules/Chains
	r.cleanACLSection(appPacketIPTableContext, appPacketIPTableSection, chainPrefix)

	// Clean Application Rules/Chains
	r.cleanACLSection(appAckPacketIPTableContext, appPacketIPTableSection, chainPrefix)

	// Clean Network Rules/Chains
	r.cleanACLSection(netPacketIPTableContext, netPacketIPTableSection, chainPrefix)

	return nil
}

func (r *ipTableUtils) FilterMarkedPackets(mark int) error {
	table := appAckPacketIPTableContext
	chain := appPacketIPTableSection
	err := r.ipt.Insert(table, chain, 1,
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
func (r *ipTableUtils) AddContainerChain(appChain string, netChain string) error {

	log.WithFields(log.Fields{
		"package":  "iptablesutils",
		"appChain": appChain,
		"netChain": netChain,
	}).Debug("Add a container chain")

	if err := r.ipt.NewChain(appPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":                 "iptablesutils",
			"appChain":                appChain,
			"netChain":                netChain,
			"appPacketIPTableContext": appPacketIPTableContext,
			"error":                   err.Error(),
		}).Debug("Failed to create the container specific chain")

		return err
	}

	if err := r.ipt.NewChain(appAckPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":                    "iptablesutils",
			"appChain":                   appChain,
			"netChain":                   netChain,
			"appAckPacketIPTableContext": appAckPacketIPTableContext,
			"error": err.Error(),
		}).Debug("Failed to create the container specific chain")

		return err
	}

	if err := r.ipt.NewChain(netPacketIPTableContext, netChain); err != nil {
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
func (r *ipTableUtils) deleteChain(context, chain string) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
		"context": context,
		"chain":   chain,
	}).Debug("Delete a chain")

	if err := r.ipt.ClearChain(context, chain); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesutils",
			"chain":   chain,
			"error":   err.Error(),
		}).Debug("Failed to clear the container specific chain")

		return err
	}

	if err := r.ipt.DeleteChain(context, chain); err != nil {
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
func (r *ipTableUtils) DeleteAllContainerChains(appChain, netChain string) error {

	log.WithFields(log.Fields{
		"package":  "iptablesutils",
		"appChain": appChain,
		"netChain": netChain,
	}).Debug("Delete all container chains")

	if err := r.deleteChain(appPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":                 "iptablesutils",
			"appChain":                appChain,
			"netChain":                netChain,
			"error":                   err.Error(),
			"appPacketIPTableContext": appPacketIPTableContext,
		}).Debug("Failed to clear and delete the appChains")

		//TODO: how do we deal with errors here
	}

	if err := r.deleteChain(appAckPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":  "iptablesutils",
			"appChain": appChain,
			"netChain": netChain,
			"error":    err.Error(),
			"appAckPacketIPTableContext": appAckPacketIPTableContext,
		}).Debug("Failed to clear and delete the appChains")
	}

	if err := r.deleteChain(netPacketIPTableContext, netChain); err != nil {
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

// addChains rules implements all the iptable rules that redirect traffic to a chain
func (r *ipTableUtils) AddChainRules(appChain string, netChain string, ip string) error {

	log.WithFields(log.Fields{
		"package":  "iptablesutils",
		"appChain": appChain,
		"netChain": netChain,
		"ip":       ip,
	}).Debug("Add chain rules")

	ChainRules := r.chainRules(appChain, netChain, ip)
	for _, cr := range ChainRules {

		if err := r.ipt.Append(cr[0], cr[1], cr[2:]...); err != nil {
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
func (r *ipTableUtils) DeleteChainRules(appChain, netChain, ip string) error {

	log.WithFields(log.Fields{
		"package":  "iptablesutils",
		"appChain": appChain,
		"netChain": netChain,
		"ip":       ip,
	}).Debug("Delete chain rules")

	ChainRules := r.chainRules(appChain, netChain, ip)
	for _, cr := range ChainRules {

		if err := r.ipt.Delete(cr[0], cr[1], cr[2:]...); err != nil {
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

// AddPacketTrap adds the necessary iptables rules to capture control packets to user space
func (r *ipTableUtils) AddPacketTrap(appChain string, netChain string, ip string, targetNetworks []string, appQueue string, netQueue string) error {

	log.WithFields(log.Fields{
		"package":  "iptablesutils",
		"appChain": appChain,
		"netChain": netChain,
		"ip":       ip,
	}).Debug("Add Packet trap")

	for _, network := range targetNetworks {

		TrapRules := r.trapRules(appChain, netChain, network, appQueue, netQueue)
		for _, tr := range TrapRules {

			if err := r.ipt.Append(tr[0], tr[1], tr[2:]...); err != nil {
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

// AddAppACLs adds a set of rules to the external services that are initiated
// by an application. The allow rules are inserted with highest priority.
func (r *ipTableUtils) AddAppACLs(chain string, ip string, rules []policy.IPRule) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
		"ip":      ip,
		"chain":   chain,
	}).Debug("Add App ACLs")

	for i := range rules {

		if err := r.ipt.Append(
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

	if err := r.ipt.Append(
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

// AddNetACLs adds iptables rules that manage traffic from external services. The
// explicit rules are added with the higest priority since they are direct allows.
func (r *ipTableUtils) AddNetACLs(chain, ip string, rules []policy.IPRule) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
		"ip":      ip,
		"rules":   rules,
		"chain":   chain,
	}).Debug("Add Net ACLs")

	for i := range rules {

		if err := r.ipt.Append(
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

	if err := r.ipt.Append(
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

func (r *ipTableUtils) cleanACLSection(context, section, chainPrefix string) {

	log.WithFields(log.Fields{
		"package":     "iptablesutils",
		"context":     context,
		"section":     section,
		"chainPrefix": chainPrefix,
	}).Debug("Clean ACL section")

	if err := r.ipt.ClearChain(context, section); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesutils",
			"context": context,
			"section": section,
			"error":   err.Error(),
		}).Debug("Can not clear the section in iptables.")
		return
	}

	rules, err := r.ipt.ListChains(context)

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
			r.ipt.ClearChain(context, rule)
			r.ipt.DeleteChain(context, rule)
		}
	}
}

// exclusionChainRules provides the list of rules that are used to send traffic to
// a particular chain
func (r *ipTableUtils) exclusionChainRules(ip string) [][]string {

	ChainRules := [][]string{
		{
			appPacketIPTableContext,
			appPacketIPTableSection,
			"-d", ip,
			"-m", "comment", "--comment", "Trireme excluded IP",
			"-j", "ACCEPT",
		},
		{
			appAckPacketIPTableContext,
			appPacketIPTableSection,
			"-d", ip,
			"-p", "tcp",
			"-m", "comment", "--comment", "Trireme excluded IP",
			"-j", "ACCEPT",
		},
		{
			netPacketIPTableContext,
			netPacketIPTableSection,
			"-s", ip,
			"-m", "comment", "--comment", "Trireme excluded IP",
			"-j", "ACCEPT",
		},
	}

	return ChainRules
}

// AddExclusionChainRules adds exclusion chain rules
func (r *ipTableUtils) AddExclusionChainRules(ip string) error {

	ChainRules := r.exclusionChainRules(ip)
	for _, cr := range ChainRules {
		if err := r.ipt.Insert(cr[0], cr[1], 1, cr[2:]...); err != nil {

			log.WithFields(log.Fields{
				"package": "supervisor",
				"error":   err.Error(),
			}).Debug("Failed to create rule that redirects to container chain")
			return err
		}
	}
	return nil
}

// DeleteExclusionChainRules removes exclusion chain rules
func (r *ipTableUtils) DeleteExclusionChainRules(ip string) error {

	ChainRules := r.exclusionChainRules(ip)
	for _, cr := range ChainRules {

		if err := r.ipt.Delete(cr[0], cr[1], cr[2:]...); err != nil {

			log.WithFields(log.Fields{
				"package": "supervisor",
				"error":   err.Error(),
			}).Debug("Failed to delete rule that redirects to container chain")
			return err
		}
	}
	return nil
}

// SetupIpset sets up an ipset
func (r *ipTableUtils) SetupIpset(name string, ips []string) error {

	ipset, err := r.ips.NewIpset(name, "hash:net", &ipset.Params{})
	if err != nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
			"error":   err.Error(),
		}).Debug("Error creating NewIPSet")
		return fmt.Errorf("Couldn't create IPSet for %s: %s", name, err)
	}

	for _, net := range ips {
		if err := ipset.Add(net, 0); err != nil {
			log.WithFields(log.Fields{
				"package": "supervisor",
				"error":   err.Error(),
			}).Debug("Error adding ip to IPSet")
			return fmt.Errorf("Error adding ip %s to %s IPSet: %s", net, name, err)
		}
	}

	r.ipset = ipset

	return nil
}

// AddIpsetOption
func (r *ipTableUtils) AddIpsetOption(ip string) error {

	return r.ipset.AddOption(ip, "nomatch", 0)
}

// DeleteIpsetOption
func (r *ipTableUtils) DeleteIpsetOption(ip string) error {

	return r.ipset.Del(ip)
}

// AddAppSetRule
func (r *ipTableUtils) AddAppSetRule(set string, ip string) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
		"ip":      ip,
		"set":     set,
	}).Debug("Add App ACLs")

	if err := r.ipt.Insert(
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
func (r *ipTableUtils) DeleteAppSetRule(set string, ip string) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
		"ip":      ip,
	}).Debug("Delete App ACLs")

	if err := r.ipt.Delete(
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
func (r *ipTableUtils) AddNetSetRule(set string, ip string) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
		"ip":      ip,
		"set":     set,
	}).Debug("Add App ACLs")

	if err := r.ipt.Insert(
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
func (r *ipTableUtils) DeleteNetSetRule(set string, ip string) error {

	log.WithFields(log.Fields{
		"package": "iptablesutils",
		"ip":      ip,
	}).Debug("Delete App ACLs")

	if err := r.ipt.Delete(
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

func (r *ipTableUtils) SetupTrapRules(set string, networkQueues string, applicationQueues string) error {

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

	for _, tr := range TrapRules {
		if err := r.ipt.Append(tr[0], tr[1], tr[2:]...); err != nil {
			log.WithFields(log.Fields{
				"package": "supervisor",
				"error":   err.Error(),
			}).Debug("Failed to add initial rules for TriremeNet IPSet.")
			return err
		}
	}
	return nil
}

func (r *ipTableUtils) CreateACLSets(set string, rules []policy.IPRule) error {
	appSet, err := r.ips.NewIpset(set, "hash:net,port", &ipset.Params{})
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

func (r *ipTableUtils) DeleteSet(set string) error {
	ipSet, err := r.ips.NewIpset(set, "hash:net,port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Couldn't create IPSet for Trireme: %s", err)
	}

	ipSet.Destroy()
	return nil
}

func (r *ipTableUtils) CleanIPSets() error {
	return r.ips.DestroyAll()
}
