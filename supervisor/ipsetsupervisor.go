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

	if iptablesProvider == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Error("IptablesProvider cannot be nil in NewIPTablesSupervisor")

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
			"package": "supervisor",
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
		"package":   "supervisor",
		"contextID": contextID,
	}).Info("Supervise PU")

	if containerInfo == nil || containerInfo.Policy == nil || containerInfo.Runtime == nil {
		log.WithFields(log.Fields{
			"package":       "supervisor",
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
		"package":   "supervisor",
		"contextID": contextID,
	}).Info("PU ContextID Already exist in Cache. Updating.")

	return s.doUpdatePU(contextID, containerInfo)
}

func (s *ipsetSupervisor) Unsupervise(contextID string) error {

	log.WithFields(log.Fields{
		"package":   "supervisor",
		"contextID": contextID,
	}).Info("Unsupervise PU")

	result, err := s.versionTracker.Get(contextID)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
		}).Error("Cannot find policy version in cache")
		return fmt.Errorf("Cannot find policy version in cache")
	}

	cacheEntry := result.(*supervisorCacheEntry)

	appSet := appChainPrefix + contextID + "-" + strconv.Itoa(cacheEntry.index)
	netSet := netChainPrefix + contextID + "-" + strconv.Itoa(cacheEntry.index)

	// Currently processing only containers with one IP address
	ip, err := defaultCacheIP(cacheEntry.ips)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
		}).Error("PU IP address not found in cache")

		return fmt.Errorf("PU IP address not found in cache: %s", err)
	}

	deleteAppSetRule(appSet, ip, s.ipt)

	deleteNetSetRule(netSet, ip, s.ipt)

	deleteSet(appSet)

	deleteSet(netSet)

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

func (s *ipsetSupervisor) doAddSets(contextID string, appSet string, netSet string, appACLs []policy.IPRule, netACLs []policy.IPRule, ip string) error {

	if err := createACLSets(appSet, appACLs); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":     "supervisor",
			"contextID":   contextID,
			"appSet":      appSet,
			"IngressACLs": appACLs,
			"error":       err,
		}).Error("Failed to create the AppSet IPSet.")
		return err
	}

	if err := createACLSets(netSet, netACLs); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":    "supervisor",
			"contextID":  contextID,
			"netSet":     netSet,
			"EgressACLs": netACLs,
			"error":      err,
		}).Error("Failed to create the NetSet IPSet.")
		return err
	}

	if err := addAppSetRule(appSet, ip, s.ipt); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"appSet":    appSet,
			"ipAddress": ip,
			"error":     err,
		}).Error("Failed to add a rule that matches the AppSet IPSet")
		return err
	}

	if err := addNetSetRule(netSet, ip, s.ipt); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"netSet":    netSet,
			"ipAddress": ip,
			"error":     err,
		}).Error("Failed to add a rule that matches the AppSet IPSet")

		return err
	}
	return nil
}

func (s *ipsetSupervisor) doCreatePU(contextID string, containerInfo *policy.PUInfo) error {

	log.WithFields(log.Fields{
		"package":   "supervisor",
		"contextID": contextID,
	}).Info("PU Creation")

	index := 0

	appSet := appChainPrefix + contextID + "-" + strconv.Itoa(index)
	netSet := netChainPrefix + contextID + "-" + strconv.Itoa(index)

	// Currently processing only containers with one IP address
	ipAddress, ok := containerInfo.Policy.DefaultIPAddress()

	if !ok {
		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
		}).Error("Default Container IP address not found in Policy")

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
			"package":   "supervisor",
			"contextID": contextID,
		}).Error("Error Versioning the policy")
		return err
	}

	if err := s.doAddSets(contextID, appSet, netSet, containerInfo.Policy.IngressACLs, containerInfo.Policy.EgressACLs, ipAddress); err != nil {
		return err
	}

	ip, _ := containerInfo.Runtime.DefaultIPAddress()
	s.collector.CollectContainerEvent(contextID, ip, containerInfo.Runtime.Tags(), "start")

	return nil
}

func (s *ipsetSupervisor) doUpdatePU(contextID string, containerInfo *policy.PUInfo) error {

	log.WithFields(log.Fields{
		"package":   "supervisor",
		"contextID": contextID,
	}).Info("PU Supervisor Update")

	cacheEntry, err := s.versionTracker.LockedModify(contextID, add, 1)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"error":     err,
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
			"contextID":  contextID,
			"cacheEntry": cacheEntry,
			"error":      err,
		}).Error("PU IP address not found in cache when updating a PU")

		return fmt.Errorf("PU IP address not found in cache: %s", err)
	}

	appSet := appChainPrefix + contextID + "-" + strconv.Itoa(newindex)
	netSet := netChainPrefix + contextID + "-" + strconv.Itoa(newindex)

	oldAppSet := appChainPrefix + contextID + "-" + strconv.Itoa(oldindex)
	oldNetSet := netChainPrefix + contextID + "-" + strconv.Itoa(oldindex)

	if err := s.doAddSets(contextID, appSet, netSet, containerInfo.Policy.IngressACLs, containerInfo.Policy.EgressACLs, ipAddress); err != nil {
		return err
	}

	deleteAppSetRule(oldAppSet, ipAddress, s.ipt)

	deleteNetSetRule(oldNetSet, ipAddress, s.ipt)

	deleteSet(oldAppSet)

	deleteSet(oldNetSet)

	ip, _ := containerInfo.Runtime.DefaultIPAddress()
	s.collector.CollectContainerEvent(contextID, ip, containerInfo.Runtime.Tags(), "update")

	return nil
}

func (s *ipsetSupervisor) createInitialIPSet() error {
	triremeSet, err := provider.NewIPset(triremeSet, "hash:net", &ipset.Params{})
	if err != nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
			"error":   err,
		}).Error("Error creating NewIPSet")
		return fmt.Errorf("Couldn't create IPSet for Trireme: %s", err)
	}
	s.triremeSet = triremeSet
	for _, net := range s.targetNetworks {
		if err := s.triremeSet.Add(net, 0); err != nil {
			log.WithFields(log.Fields{
				"package": "supervisor",
				"error":   err,
			}).Error("Error adding network  to Trireme IPSet")
			return fmt.Errorf("Error adding network %s to Trireme IPSet: %s", net, err)
		}
	}
	return nil
}

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
				"package": "supervisor",
				"error":   err,
			}).Error("Failed to add initial rules for TriremeNet IPSet.")
			return err
		}
	}
	return nil
}

func (s *ipsetSupervisor) cleanACLs() error {
	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
	}).Info("Cleaning all IPTables")

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
	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
		"excludedIP": ip,
	}).Info("Adding ExclusionIP")
	return s.triremeSet.AddOption(ip, "nomatch", 0)
}

func (s *ipsetSupervisor) RemoveExcludedIP(ip string) error {
	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
		"excludedIP": ip,
	}).Info("Removing ExclusionIP")
	return s.triremeSet.Del(ip)
}
