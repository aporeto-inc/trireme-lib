package supervisor

import (
	"fmt"
	"strconv"

	"github.com/aporeto-inc/trireme/cache"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/provider"
	"github.com/bvandewalle/go-ipset/ipset"
)

const triremeSet = "TriremeSet"

type ipsetSupervisor struct {
	versionTracker    cache.DataStore
	ipt               provider.IptablesProvider
	collector         collector.EventCollector
	networkQueues     string
	applicationQueues string
	targetNetworks    []string
	triremeSet        provider.IpsetProvider
}

// NewIPSetSupervisor returns a new implementation of the Supervisor based on IPSets.
func NewIPSetSupervisor(collector collector.EventCollector, enforcer enforcer.PolicyEnforcer, iptablesProvider provider.IptablesProvider, targetNetworks []string) (Supervisor, error) {
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

	deleteAppACLs(appChain, ip, cacheEntry.ingressACLs, s.ipt)

	deleteNetACLs(netChain, ip, cacheEntry.egressACLs, s.ipt)

	deleteChainRules(appChain, netChain, ip, s.ipt)

	deleteAllContainerChains(appChain, netChain, s.ipt)

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

	appSet := appChainPrefix + contextID + "-" + strconv.Itoa(index)
	netSet := netChainPrefix + contextID + "-" + strconv.Itoa(index)

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

	if err := createACLSets(appSet, containerInfo.Policy.IngressACLs); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":     "supervisor",
			"supervisor":  s,
			"contextID":   contextID,
			"appSet":      appSet,
			"ingressACLs": containerInfo.Policy.IngressACLs,
			"error":       err,
		}).Error("Failed to add the new chain app acls rules when creating a PU")

		return err
	}

	if err := createACLSets(netSet, containerInfo.Policy.EgressACLs); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":     "supervisor",
			"supervisor":  s,
			"contextID":   contextID,
			"netSet":      netSet,
			"ingressACLs": containerInfo.Policy.EgressACLs,
			"error":       err,
		}).Error("Failed to add the new chain app acls rules when creating a PU")

		return err
	}

	if err := addAppSetRule(appSet, ipAddress, s.ipt); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"contextID":  contextID,
			"egressACLs": containerInfo.Policy.EgressACLs,
			"error":      err,
		}).Error("Failed to add the new chain net acls rules when updating a PU")

		return err
	}

	if err := addNetSetRule(netSet, ipAddress, s.ipt); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"contextID":  contextID,
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
	if err := addContainerChain(appChain, netChain, s.ipt); err != nil {
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

	if err := addAppACLs(appChain, ipAddress, containerInfo.Policy.IngressACLs, s.ipt); err != nil {
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

	if err := addNetACLs(netChain, ipAddress, containerInfo.Policy.EgressACLs, s.ipt); err != nil {
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
	if err := addChainRules(appChain, netChain, ipAddress, s.ipt); err != nil {
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

	if err := deleteChainRules(oldAppChain, oldNetChain, ipAddress, s.ipt); err != nil {
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
	if err := deleteAllContainerChains(oldAppChain, oldNetChain, s.ipt); err != nil {
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
	triremeSet, err := provider.NewIPset(triremeSet, "hash:net", &ipset.Params{})
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

func (s *ipsetSupervisor) cleanACLs() error {
	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
	}).Info("Clean all ACL")

	// Clean Application Rules/Chains
	cleanACLSection(appPacketIPTableContext, appPacketIPTableSection, chainPrefix, s.ipt)

	// Clean Application Rules/Chains
	cleanACLSection(appAckPacketIPTableContext, appPacketIPTableSection, chainPrefix, s.ipt)

	// Clean Application Rules/Chains
	cleanACLSection(appAckPacketIPTableContext, appPacketIPTableSection, chainPrefix, s.ipt)

	// Clean Network Rules/Chains
	cleanACLSection(netPacketIPTableContext, netPacketIPTableSection, chainPrefix, s.ipt)

	return nil
}

func (s *ipsetSupervisor) AddExcludedIP(ip string) error {
	return s.triremeSet.AddOption(ip, "nomatch", 0)
}

func (s *ipsetSupervisor) RemoveExcludedIP(ip string) error {
	return s.triremeSet.Del(ip)
}
