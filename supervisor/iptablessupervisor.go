package supervisor

import (
	"fmt"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/provider"
	"github.com/golang/glog"
)

type supervisorCacheEntry struct {
	index       int
	ips         []string
	ingressACLs []policy.IPRule
	egressACLs  []policy.IPRule
}

// iptablesSupervisor is the structure holding all information about a connection filter
type iptablesSupervisor struct {
	versionTracker    cache.DataStore
	ipt               provider.IptablesProvider
	collector         collector.EventCollector
	networkQueues     string
	applicationQueues string
	targetNetworks    []string
}

// NewIPTablesSupervisor will create a new connection supervisor that uses IPTables
// to redirect specific packets to userspace. It instantiates multiple data stores
// to maintain efficient mappings between contextID, policy and IP addresses. This
// simplifies the lookup operations at the expense of memory.
func NewIPTablesSupervisor(collector collector.EventCollector, enforcer enforcer.PolicyEnforcer, iptablesProvider provider.IptablesProvider, targetNetworks []string) (Supervisor, error) {

	if collector == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Error("Collector cannot be nil in NewIPTablesSupervisor")

		return nil, fmt.Errorf("Collector cannot be nil")
	}

	if enforcer == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Error("Enforcer cannot be nil in NewIPTablesSupervisor")

		return nil, fmt.Errorf("Enforcer cannot be nil")
	}

	if targetNetworks == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Error("TargetNetworks cannot be nil in NewIPTablesSupervisor")

		return nil, fmt.Errorf("TargetNetworks cannot be nil")
	}

	filterQueue := enforcer.GetFilterQueue()

	if filterQueue == nil {
		log.WithFields(log.Fields{
			"package":  "supervisor",
			"enforcer": enforcer,
		}).Error("Enforcer FilterQueues cannot be nil in NewIPTablesSupervisor")

		return nil, fmt.Errorf("Enforcer FilterQueues cannot be nil")
	}

	s := &iptablesSupervisor{
		ipt:               iptablesProvider,
		versionTracker:    cache.NewCache(nil),
		targetNetworks:    targetNetworks,
		collector:         collector,
		networkQueues:     strconv.Itoa(int(filterQueue.NetworkQueue)) + ":" + strconv.Itoa(int(filterQueue.NetworkQueue+filterQueue.NumberOfNetworkQueues-1)),
		applicationQueues: strconv.Itoa(int(filterQueue.ApplicationQueue)) + ":" + strconv.Itoa(int(filterQueue.ApplicationQueue+filterQueue.NumberOfApplicationQueues-1)),
	}

	// Clean any previous ACLs that we have installed
	s.CleanACL()

	return s, nil
}

// Supervise creates a mapping between an IP address and the corresponding labels.
// it invokes the various handlers that process the parameter policy.
func (s *iptablesSupervisor) Supervise(contextID string, containerInfo *policy.PUInfo) error {

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

// Unsupervise removes the mapping from cache and cleans up the iptable rules. ALL
// remove operations will print errors by they don't return error. We want to force
// as much cleanup as possible to avoid stale state
func (s *iptablesSupervisor) Unsupervise(contextID string) error {

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

	deletePacketTrap(appChain, netChain, ip, s.targetNetworks, s.applicationQueues, s.networkQueues, s.ipt)

	deleteAppACLs(appChain, ip, cacheEntry.ingressACLs, s.ipt)

	deleteNetACLs(netChain, ip, cacheEntry.egressACLs, s.ipt)

	deleteChainRules(appChain, netChain, ip, s.ipt)

	deleteAllContainerChains(appChain, netChain, s.ipt)

	s.versionTracker.Remove(contextID)

	return nil
}

// Start starts the supervisor
func (s *iptablesSupervisor) Start() error {
	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
	}).Info("Start the supervisor")

	return nil
}

// Stop stops the supervisor
func (s *iptablesSupervisor) Stop() error {
	log.WithFields(log.Fields{
		"package":    "supervisor",
		"supervisor": s,
	}).Info("Stop the supervisor")

	// Clean any previous ACLs that we have installed
	s.CleanACL()
	return nil
}

func (s *iptablesSupervisor) doCreatePU(contextID string, containerInfo *policy.PUInfo) error {

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
	if err := addContainerChain(appChain, netChain, s.ipt); err != nil {
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
		}).Error("Failed to add the new chain rules when creating a PU")

		return err
	}

	if err := addPacketTrap(appChain, netChain, ipAddress, s.targetNetworks, s.applicationQueues, s.networkQueues, s.ipt); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"contextID":  contextID,
			"appChain":   appChain,
			"netChain":   netChain,
			"ipAddress":  ipAddress,
			"error":      err,
		}).Error("Failed to add the packet trap rule when creating a PU")

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
		}).Error("Failed to add the new chain app acls rules when creating a PU")

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

	ip, _ := containerInfo.Runtime.DefaultIPAddress()
	s.collector.CollectContainerEvent(contextID, ip, containerInfo.Runtime.Tags(), "start")

	return nil
}

// UpdatePU creates a mapping between an IP address and the corresponding labels
//and the invokes the various handlers that process all policies.
func (s *iptablesSupervisor) doUpdatePU(contextID string, containerInfo *policy.PUInfo) error {

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

	if err := addPacketTrap(appChain, netChain, ipAddress, s.targetNetworks, s.applicationQueues, s.networkQueues, s.ipt); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":    "supervisor",
			"supervisor": s,
			"contextID":  contextID,
			"appChain":   appChain,
			"netChain":   netChain,
			"ipAddress":  ipAddress,
			"error":      err,
		}).Error("Failed to add the packet trap rule when updating a PU")

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

// CleanACL cleans up all the ACLs that have an Trireme  Label in the mangle table
func (s *iptablesSupervisor) CleanACL() {

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
}

// exclusionChainRules provides the list of rules that are used to send traffic to
// a particular chain
func (s *iptablesSupervisor) exclusionChainRules(ip string) [][]string {

	chainRules := [][]string{
		{
			appPacketIPTableContext,
			appPacketIPTableSection,
			"-d", ip,
			"-m", "comment", "--comment", "Trireme excluded IP",
			"-j", "ACCEPT",
		},
		{appAckPacketIPTableContext,
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

	return chainRules
}

// AddExcludedIP adds an exception for the destination parameter IP, allowing all the traffic.
func (s *iptablesSupervisor) AddExcludedIP(ip string) error {
	chainRules := s.exclusionChainRules(ip)
	for _, cr := range chainRules {
		if err := s.ipt.Insert(cr[0], cr[1], 1, cr[2:]...); err != nil {
			glog.V(2).Infoln("Failed to create "+cr[0]+":"+cr[1]+" rule that redirects to container chain", err)
			return err
		}
	}
	return nil
}

// RemoveExcludedIP removes the exception for the destion IP given in parameter.
func (s *iptablesSupervisor) RemoveExcludedIP(ip string) error {

	chainRules := s.exclusionChainRules(ip)
	for _, cr := range chainRules {

		if err := s.ipt.Delete(cr[0], cr[1], cr[2:]...); err != nil {
			glog.V(2).Infoln("Failed to delete "+cr[0]+":"+cr[1]+" rule that redirects to container chain", err)
			return err
		}
	}
	return nil
}

func add(a, b interface{}) interface{} {
	entry := a.(*supervisorCacheEntry)
	entry.index += b.(int)
	return entry
}
