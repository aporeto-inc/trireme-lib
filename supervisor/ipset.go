package supervisor

import (
	"fmt"
	"strconv"

	"github.com/aporeto-inc/trireme/cache"

	log "github.com/Sirupsen/logrus"
	"github.com/janeczku/go-ipset/ipset"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/policy"
)

const triremeSet = "TriremeSet"

type ipsetSupervisor struct {
	versionTracker    cache.DataStore
	ipt               IptablesProvider
	collector         collector.EventCollector
	networkQueues     string
	applicationQueues string
	targetNetworks    []string
	triremeSet        IpsetProvider
}

// NewIPSetSupervisor returns a new implementation of the Supervisor based on IPSets.
func NewIPSetSupervisor(collector collector.EventCollector, enforcer enforcer.PolicyEnforcer, iptablesProvider IptablesProvider, targetNetworks []string) (Supervisor, error) {
	if collector == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Error("Collector cannot be nil in NewIPSetSupervisor")

		return nil, fmt.Errorf("Collector cannot be nil")
	}

	if enforcer == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Error("Enforcer cannot be nil in NewIPSetSupervisor")

		return nil, fmt.Errorf("Enforcer cannot be nil")
	}

	if targetNetworks == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Error("TargetNetworks cannot be nil in NewIPSetSupervisor")

		return nil, fmt.Errorf("TargetNetworks cannot be nil")
	}

	filterQueue := enforcer.GetFilterQueue()

	if filterQueue == nil {
		log.WithFields(log.Fields{
			"package":  "supervisor",
			"enforcer": enforcer,
		}).Error("Enforcer FilterQueues cannot be nil in NewIPSetSupervisor")

		return nil, fmt.Errorf("Enforcer FilterQueues cannot be nil")
	}

	s := &ipsetSupervisor{
		ipt:               iptablesProvider,
		versionTracker:    cache.NewCache(nil),
		targetNetworks:    targetNetworks,
		collector:         collector,
		networkQueues:     strconv.Itoa(int(filterQueue.NetworkQueue)) + ":" + strconv.Itoa(int(filterQueue.NetworkQueue+filterQueue.NumberOfNetworkQueues-1)),
		applicationQueues: strconv.Itoa(int(filterQueue.ApplicationQueue)) + ":" + strconv.Itoa(int(filterQueue.ApplicationQueue+filterQueue.NumberOfApplicationQueues-1)),
	}

	return s, nil
}

func (s *ipsetSupervisor) Supervise(contextID string, containerInfo *policy.PUInfo) error {
	log.WithFields(log.Fields{
		"package":       "supervisor",
		"supervisor":    s,
		"contextID":     contextID,
		"containerInfo": containerInfo,
	}).Info("Supervise the given contextID and containerInfo")

	if containerInfo == nil || containerInfo.Policy == nil || containerInfo.Runtime == nil {
		log.WithFields(log.Fields{
			"package":       "supervisor",
			"supervisor":    s,
			"containerInfo": containerInfo,
		}).Error("Runtime issue, Policy and ContainerInfo should not be nil")

		return fmt.Errorf("Runtime, Policy and ContainerInfo should not be nil")
	}

	_, err := s.versionTracker.Get(contextID)

	if err != nil {
		// ContextID is not found in Cache, New PU: Do create.
		return s.doCreatePU(contextID, containerInfo)
	}

	log.WithFields(log.Fields{
		"package":       "supervisor",
		"supervisor":    s,
		"contextID":     contextID,
		"containerInfo": containerInfo,
	}).Info("ContextID Already exist in Cache. Do Update on the PU")

	return s.doUpdatePU(contextID, containerInfo)
}

func (s *ipsetSupervisor) Unsupervise(contextID string) error {

	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
		"contextID":  contextID,
	}).Info("Unsupervise the given contextID, clean the iptable rules")

	result, err := s.versionTracker.Get(contextID)

	if err != nil {
		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"contextID":  contextID,
		}).Error("Cannot find policy version!")

		return fmt.Errorf("Cannot find policy version!")
	}

	cacheEntry := result.(*supervisorCacheEntry)

	appChain := appChainPrefix + contextID + "-" + strconv.Itoa(cacheEntry.index)
	netChain := netChainPrefix + contextID + "-" + strconv.Itoa(cacheEntry.index)

	// Currently processing only containers with one IP address
	ip, err := defaultCacheIP(cacheEntry.ips)

	if err != nil {
		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"contextID":  contextID,
			"cacheEntry": cacheEntry,
		}).Error("Container IP address not found in cache")

		return fmt.Errorf("Container IP address not found in cache: %s", err)
	}

	s.deleteAppACLs(appChain, ip, cacheEntry.ingressACLs)

	s.deleteNetACLs(netChain, ip, cacheEntry.egressACLs)

	s.deleteChainRules(appChain, netChain, ip)

	s.deleteAllContainerChains(appChain, netChain)

	s.versionTracker.Remove(contextID)

	return nil
}

func (s *ipsetSupervisor) Start() error {
	if err := s.createInitialIPSet(); err != nil {
		return err
	}
	if err := s.createInitialRules(); err != nil {
		return err
	}
	return nil
}

func (s *ipsetSupervisor) Stop() error {
	s.cleanACLs()
	return nil
}

func (s *ipsetSupervisor) doCreatePU(contextID string, containerInfo *policy.PUInfo) error {

	log.WithFields(log.Fields{
		"package":       "supervisor",
		"supervisor":    s,
		"contextID":     contextID,
		"containerInfo": containerInfo,
	}).Info("IPTables update for the creation of a pu")

	index := 0

	appChain := appChainPrefix + contextID + "-" + strconv.Itoa(index)
	netChain := netChainPrefix + contextID + "-" + strconv.Itoa(index)

	// Currently processing only containers with one IP address
	ipAddress, ok := containerInfo.Policy.DefaultIPAddress()

	if !ok {
		log.WithFields(log.Fields{
			"package":       "supervisor",
			"supervisor":    s,
			"contextID":     contextID,
			"containerInfo": containerInfo,
		}).Error("Container IP address not found when creatin a PU")

		return fmt.Errorf("Container IP address not found")
	}

	cacheEntry := &supervisorCacheEntry{
		index:       index,
		ips:         containerInfo.Policy.IPAddresses(),
		ingressACLs: containerInfo.Policy.IngressACLs,
		egressACLs:  containerInfo.Policy.EgressACLs,
	}

	// Version the policy so that we can do hitless policy changes
	if err := s.versionTracker.AddOrUpdate(contextID, cacheEntry); err != nil {
		s.Unsupervise(contextID)
		log.WithFields(log.Fields{
			"package":       "supervisor",
			"supervisor":    s,
			"contextID":     contextID,
			"containerInfo": containerInfo,
			"cacheEntry":    cacheEntry,
		}).Error("Version the policy so that we can do hitless policy changes failed when creatin a PU")
		return err
	}

	// Configure all the ACLs
	if err := s.addContainerChain(appChain, netChain); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"contextID":  contextID,
			"appChain":   appChain,
			"netChain":   netChain,
			"error":      err,
		}).Error("Failed to add containerInfo chain rule when ceating a PU")

		return err
	}

	if err := s.addChainRules(appChain, netChain, ipAddress); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"contextID":  contextID,
			"appChain":   appChain,
			"netChain":   netChain,
			"ipAddress":  ipAddress,
			"error":      err,
		}).Error("Failed to add the new chain rules when creating a PU")

		return err
	}

	if err := s.addAppACLs(appChain, ipAddress, containerInfo.Policy.IngressACLs); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":     "supervisor",
			"supervisor":  s,
			"contextID":   contextID,
			"appChain":    appChain,
			"ingressACLs": containerInfo.Policy.IngressACLs,
			"error":       err,
		}).Error("Failed to add the new chain app acls rules when creating a PU")

		return err
	}

	if err := s.addNetACLs(netChain, ipAddress, containerInfo.Policy.EgressACLs); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"contextID":  contextID,
			"netChain":   netChain,
			"egressACLs": containerInfo.Policy.EgressACLs,
			"error":      err,
		}).Error("Failed to add the new chain net acls rules when updating a PU")

		return err
	}

	ip, _ := containerInfo.Runtime.DefaultIPAddress()
	s.collector.CollectContainerEvent(contextID, ip, containerInfo.Runtime.Tags(), "start")

	return nil
}

// UpdatePU creates a mapping between an IP address and the corresponding labels
//and the invokes the various handlers that process all policies.
func (s *ipsetSupervisor) doUpdatePU(contextID string, containerInfo *policy.PUInfo) error {

	log.WithFields(log.Fields{
		"package":       "supervisor",
		"supervisor":    s,
		"contextID":     contextID,
		"containerInfo": containerInfo,
	}).Info("IPTables update for the update of a pu")

	cacheEntry, err := s.versionTracker.LockedModify(contextID, add, 1)

	if err != nil {
		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"contextID":  contextID,
			"error":      err,
		}).Error("Error finding PU in cache")

		return fmt.Errorf("Error finding PU in cache %s", err)
	}

	cachedEntry := cacheEntry.(*supervisorCacheEntry)
	newindex := cachedEntry.index
	oldindex := newindex - 1

	// Currently processing only containers with one IP address
	ipAddress, err := defaultCacheIP(cachedEntry.ips)

	if err != nil {
		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"contextID":  contextID,
			"cacheEntry": cacheEntry,
			"error":      err,
		}).Error("Container IP address not found in cache when updating a PU")

		return fmt.Errorf("Container IP address not found in cache: %s", err)
	}

	appChain := appChainPrefix + contextID + "-" + strconv.Itoa(newindex)
	netChain := netChainPrefix + contextID + "-" + strconv.Itoa(newindex)

	oldAppChain := appChainPrefix + contextID + "-" + strconv.Itoa(oldindex)
	oldNetChain := netChainPrefix + contextID + "-" + strconv.Itoa(oldindex)

	//Add a new chain for this update and map all rules there
	if err := s.addContainerChain(appChain, netChain); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"contextID":  contextID,
			"appChain":   oldAppChain,
			"netChain":   oldNetChain,
			"error":      err,
		}).Error("Failed to add container chain rule when updating a PU")

		return err
	}

	if err := s.addAppACLs(appChain, ipAddress, containerInfo.Policy.IngressACLs); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":     "supervisor",
			"supervisor":  s,
			"contextID":   contextID,
			"appChain":    appChain,
			"ingressACLs": containerInfo.Policy.IngressACLs,
			"error":       err,
		}).Error("Failed to add the new chain app acls rules when updating a PU")

		return err
	}

	if err := s.addNetACLs(netChain, ipAddress, containerInfo.Policy.EgressACLs); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"contextID":  contextID,
			"netChain":   netChain,
			"egressACLs": containerInfo.Policy.EgressACLs,
			"error":      err,
		}).Error("Failed to add the new chain net acls rules when updating a PU")

		return err
	}

	// Add mapping to new chain
	if err := s.addChainRules(appChain, netChain, ipAddress); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"contextID":  contextID,
			"appChain":   appChain,
			"netChain":   netChain,
			"ipAddress":  ipAddress,
			"error":      err,
		}).Error("Failed to add the new chain rules when updating a PU")

		return err
	}

	//Remove mapping from old chain

	if err := s.deleteChainRules(oldAppChain, oldNetChain, ipAddress); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":     "supervisor",
			"supervisor":  s,
			"contextID":   contextID,
			"oldAppChain": oldAppChain,
			"oldNetChain": oldNetChain,
			"ipAddress":   ipAddress,
			"error":       err,
		}).Error("Failed to remove the old chain rules when updating a PU")

		return err
	}

	// Delete the old chain to clean up
	if err := s.deleteAllContainerChains(oldAppChain, oldNetChain); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":     "supervisor",
			"supervisor":  s,
			"contextID":   contextID,
			"oldAppChain": oldAppChain,
			"oldNetChain": oldNetChain,
			"error":       err,
		}).Error("Failed to delete the old chain container rules when updating a PU")

		return err
	}

	ip, _ := containerInfo.Runtime.DefaultIPAddress()
	s.collector.CollectContainerEvent(contextID, ip, containerInfo.Runtime.Tags(), "update")

	return nil
}

func (s *ipsetSupervisor) createInitialIPSet() error {
	triremeSet, err := NewIPset(triremeSet, "hash:net", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Couldn't create IPSet for Trireme: %s", err)
	}
	s.triremeSet = triremeSet
	for _, net := range s.targetNetworks {
		if err := s.triremeSet.Add(net, 0); err != nil {
			return fmt.Errorf("Error adding network %s to Trireme IPSet: %s", net, err)
		}
	}
	return nil
}

//trapRules provides the packet trap rules to add/delete
func (s *ipsetSupervisor) trapRulesSet(set string) [][]string {

	trapRules := [][]string{
		// Application Syn and Syn/Ack
		{
			appPacketIPTableContext, appPacketIPTableSection,
			"-m", "set", "--match-set", set, "dst",
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "NFQUEUE", "--queue-balance", s.applicationQueues,
		},

		// Application everything else
		{
			appAckPacketIPTableContext, appPacketIPTableSection,
			"-m", "set", "--match-set", set, "dst",
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "ACCEPT",
		},

		// Application everything else
		{
			appAckPacketIPTableContext, appPacketIPTableSection,
			"-m", "set", "--match-set", set, "dst",
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", s.applicationQueues,
		},

		// Network side rules
		{
			netPacketIPTableContext, netPacketIPTableSection,
			"-m", "set", "--match-set", set, "src",
			"-p", "tcp",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", s.networkQueues,
		},
	}

	return trapRules
}

func (s *ipsetSupervisor) createInitialRules() error {
	trapRules := s.trapRulesSet(triremeSet)
	for _, tr := range trapRules {
		fmt.Printf("LALALA: %+v", tr)
		if err := s.ipt.Append(tr[0], tr[1], tr[2:]...); err != nil {
			log.WithFields(log.Fields{
				"package":     "supervisor",
				"supervisor":  s,
				"trapRule[0]": tr[0],
				"trapRule[1]": tr[1],
				"error":       err,
			}).Error("Failed to add the rule that redirects to container chain for packet trap")
			return err
		}
	}

	return nil
}

// addContainerChain adds a chain for the specific container and redirects traffic there
// This simplifies significantly the management and makes the iptable rules more readable
// All rules related to a container are contained within the dedicated chain
func (s *ipsetSupervisor) addContainerChain(appChain string, netChain string) error {

	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
		"appChain":   appChain,
		"netChain":   netChain,
	}).Info("Add a container chain")

	if err := s.ipt.NewChain(appPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"supervisor":              s,
			"appChain":                appChain,
			"netChain":                netChain,
			"appPacketIPTableContext": appPacketIPTableContext,
			"error":                   err,
		}).Error("Failed to create the container specific chain")

		return err
	}

	if err := s.ipt.NewChain(appAckPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":                    "supervisor",
			"supervisor":                 s,
			"appChain":                   appChain,
			"netChain":                   netChain,
			"appAckPacketIPTableContext": appAckPacketIPTableContext,
			"error": err,
		}).Error("Failed to create the container specific chain")

		return err
	}

	if err := s.ipt.NewChain(netPacketIPTableContext, netChain); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"supervisor":              s,
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
func (s *ipsetSupervisor) deleteChain(context, chain string) error {

	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
		"context":    context,
		"chain":      chain,
	}).Info("Delete a chain")

	if err := s.ipt.ClearChain(context, chain); err != nil {
		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"chain":      chain,
			"error":      err,
		}).Error("Failed to clear the container specific chain")

		return err
	}

	if err := s.ipt.DeleteChain(context, chain); err != nil {
		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"chain":      chain,
			"error":      err,
		}).Error("Failed to delete the container specific chain")

		return err
	}

	return nil
}

// deleteAllContainerChains removes all the container specific chains and basic rules
func (s *ipsetSupervisor) deleteAllContainerChains(appChain, netChain string) error {

	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
		"appChain":   appChain,
		"netChain":   netChain,
	}).Info("Delete all container chains")

	if err := s.deleteChain(appPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"supervisor":              s,
			"appChain":                appChain,
			"netChain":                netChain,
			"error":                   err,
			"appPacketIPTableContext": appPacketIPTableContext,
		}).Error("Failed to clear and delete the appChains")

		//TODO: how do we deal with errors here
	}

	if err := s.deleteChain(appAckPacketIPTableContext, appChain); err != nil {
		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"appChain":   appChain,
			"netChain":   netChain,
			"error":      err,
			"appAckPacketIPTableContext": appAckPacketIPTableContext,
		}).Error("Failed to clear and delete the appChains")

		//TODO: how do we deal with errors here
	}

	if err := s.deleteChain(netPacketIPTableContext, netChain); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"supervisor":              s,
			"appChain":                appChain,
			"netChain":                netChain,
			"error":                   err,
			"netPacketIPTableContext": netPacketIPTableContext,
		}).Error("Failed to clear and delete the netChain")

		//TODO: how do we deal with errors here
	}

	return nil
}

// chainRules provides the list of rules that are used to send traffic to
// a particular chain
func (s *ipsetSupervisor) chainRules(appChain string, netChain string, ip string) [][]string {

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
func (s *ipsetSupervisor) addChainRules(appChain string, netChain string, ip string) error {

	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
		"appChain":   appChain,
		"netChain":   netChain,
		"ip":         ip,
	}).Info("Add chain rules")

	chainRules := s.chainRules(appChain, netChain, ip)
	for _, cr := range chainRules {

		if err := s.ipt.Append(cr[0], cr[1], cr[2:]...); err != nil {
			log.WithFields(log.Fields{
				"package":       "supervisor",
				"supervisor":    s,
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
func (s *ipsetSupervisor) deleteChainRules(appChain, netChain, ip string) error {

	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
		"appChain":   appChain,
		"netChain":   netChain,
		"ip":         ip,
	}).Info("Delete chain rules")

	chainRules := s.chainRules(appChain, netChain, ip)
	for _, cr := range chainRules {

		if err := s.ipt.Delete(cr[0], cr[1], cr[2:]...); err != nil {
			log.WithFields(log.Fields{
				"package":       "supervisor",
				"supervisor":    s,
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

// addAppACLs adds a set of rules to the external services that are initiated
// by an application. The allow rules are inserted with highest priority.
func (s *ipsetSupervisor) addAppACLs(chain string, ip string, rules []policy.IPRule) error {

	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
		"ip":         ip,
		"rules":      rules,
		"chain":      chain,
	}).Info("Add App ACLs")

	for i := range rules {

		if err := s.ipt.Append(
			appAckPacketIPTableContext, chain,
			"-p", rules[i].Protocol, "-m", "state", "--state", "NEW",
			"-d", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			log.WithFields(log.Fields{
				"package":                 "supervisor",
				"supervisor":              s,
				"netPacketIPTableContext": netPacketIPTableContext,
				"chain":                   chain,
				"rule":                    rules[i],
				"error":                   err,
			}).Error("Error when adding app acl rule")
			return err
		}

	}

	if err := s.ipt.Append(
		appAckPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP"); err != nil {

		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"supervisor":              s,
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   chain,
			"error":                   err,
		}).Error("Error when adding default app acl rule")

		return err
	}

	return nil
}

// deleteAppACLs deletes the rules associated with traffic to external services
func (s *ipsetSupervisor) deleteAppACLs(chain string, ip string, rules []policy.IPRule) error {

	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
		"ip":         ip,
		"rules":      rules,
		"chain":      chain,
	}).Info("Delete App ACLs")

	for i := range rules {
		if err := s.ipt.Delete(
			appAckPacketIPTableContext, chain,
			"-p", rules[i].Protocol, "-m", "state", "--state", "NEW",
			"-d", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			log.WithFields(log.Fields{
				"package":                 "supervisor",
				"supervisor":              s,
				"netPacketIPTableContext": netPacketIPTableContext,
				"chain":                   chain,
				"rule":                    rules[i],
				"error":                   err,
			}).Error("Error when removing ingress app acl rule")

			// TODO: how do we deal with errors ?
		}
	}

	if err := s.ipt.Delete(
		appAckPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP",
	); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"supervisor":              s,
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   chain,
			"error":                   err,
		}).Error("Error when removing default ingress app acl default rule")
	}

	return nil
}

// addNetACLs adds iptables rules that manage traffic from external services. The
// explicit rules are added with the higest priority since they are direct allows.
func (s *ipsetSupervisor) addNetACLs(chain, ip string, rules []policy.IPRule) error {

	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
		"ip":         ip,
		"rules":      rules,
		"chain":      chain,
	}).Info("Add Net ACLs")

	for i := range rules {

		if err := s.ipt.Append(
			netPacketIPTableContext, chain,
			"-p", rules[i].Protocol,
			"-s", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			log.WithFields(log.Fields{
				"package":                 "supervisor",
				"supervisor":              s,
				"netPacketIPTableContext": netPacketIPTableContext,
				"chain":                   chain,
				"error":                   err,
				"rule":                    rules[i],
			}).Error("Error when adding a net acl rule")

			return err
		}

	}

	if err := s.ipt.Append(
		netPacketIPTableContext, chain,
		"-s", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP",
	); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"supervisor":              s,
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   chain,
			"error":                   err,
		}).Error("Error when adding default net acl rule")

		return err
	}

	return nil
}

// deleteNetACLs removes the iptable rules that manage traffic from external services
func (s *ipsetSupervisor) deleteNetACLs(chain string, ip string, rules []policy.IPRule) error {

	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
		"ip":         ip,
		"rules":      rules,
		"chain":      chain,
	}).Info("Delete Net ACLs")

	for i := range rules {
		if err := s.ipt.Delete(
			netPacketIPTableContext, chain,
			"-p", rules[i].Protocol,
			"-s", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			log.WithFields(log.Fields{
				"package":                 "supervisor",
				"supervisor":              s,
				"netPacketIPTableContext": netPacketIPTableContext,
				"chain":                   chain,
				"rule":                    rules[i],
				"error":                   err,
			}).Error("Error when removing the egress net ACL rule")

			// TODO: how do we deal with the errors here
		}
	}

	if err := s.ipt.Delete(
		netPacketIPTableContext, chain,
		"-s", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP",
	); err != nil {
		log.WithFields(log.Fields{
			"package":                 "supervisor",
			"supervisor":              s,
			"netPacketIPTableContext": netPacketIPTableContext,
			"chain":                   chain,
			"error":                   err,
		}).Error("Error when removing the net ACL rule")
	}

	return nil
}

func (s *ipsetSupervisor) cleanACLs() error {
	return nil
}

func (s *ipsetSupervisor) AddExcludedIP(ip string) error {
	return nil
}

func (s *ipsetSupervisor) RemoveExcludedIP(ip string) error {
	return nil
}
