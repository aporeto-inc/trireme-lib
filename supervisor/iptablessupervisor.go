package supervisor

import (
	"fmt"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/iptablesutils"
	"github.com/aporeto-inc/trireme/supervisor/provider"
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
	ipu               iptablesutils.IptableUtils
	collector         collector.EventCollector
	networkQueues     string
	applicationQueues string
	targetNetworks    []string
	Mark              int
	remote            bool
}

// NewIPTablesSupervisor will create a new connection supervisor that uses IPTables
// to redirect specific packets to userspace. It instantiates multiple data stores
// to maintain efficient mappings between contextID, policy and IP addresses. This
// simplifies the lookup operations at the expense of memory.

func NewIPTablesSupervisor(collector collector.EventCollector, enforcer enforcer.PolicyEnforcer, iptablesProvider provider.IptablesProvider, targetNetworks []string, remote bool) (Supervisor, error) {

	if collector == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Debug("Collector cannot be nil in NewIPTablesSupervisor")

		return nil, fmt.Errorf("Collector cannot be nil")
	}

	if enforcerInstance == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Debug("Enforcer cannot be nil in NewIPTablesSupervisor")

		return nil, fmt.Errorf("Enforcer cannot be nil")
	}

	if iptablesUtils == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Debug("IptablesUtils cannot be nil in NewIPTablesSupervisor")

		return nil, fmt.Errorf("Enforcer cannot be nil")
	}

	if targetNetworks == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Debug("TargetNetworks cannot be nil in NewIPTablesSupervisor")

		return nil, fmt.Errorf("TargetNetworks cannot be nil")
	}

	filterQueue := enforcerInstance.GetFilterQueue()

	if filterQueue == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Debug("Enforcer FilterQueues cannot be nil in NewIPTablesSupervisor")

		return nil, fmt.Errorf("Enforcer FilterQueues cannot be nil")
	}

	s := &iptablesSupervisor{
		ipu:               iptablesUtils,
		versionTracker:    cache.NewCache(nil),
		targetNetworks:    targetNetworks,
		collector:         collector,
		networkQueues:     strconv.Itoa(int(filterQueue.NetworkQueue)) + ":" + strconv.Itoa(int(filterQueue.NetworkQueue+filterQueue.NumberOfNetworkQueues-1)),
		applicationQueues: strconv.Itoa(int(filterQueue.ApplicationQueue)) + ":" + strconv.Itoa(int(filterQueue.ApplicationQueue+filterQueue.NumberOfApplicationQueues-1)),
		Mark:              enforcer.DefaultMarkValue,
		remote:            remote,
	}

	// Clean any previous ACLs that we have installed
	s.CleanACL()

	return s, nil
}

// Supervise creates a mapping between an IP address and the corresponding labels.
// it invokes the various handlers that process the parameter policy.
func (s *iptablesSupervisor) Supervise(contextID string, containerInfo *policy.PUInfo) error {

	log.WithFields(log.Fields{
		"package":   "supervisor",
		"contextID": contextID,
	}).Debug("Supervise PU")

	if containerInfo == nil || containerInfo.Policy == nil || containerInfo.Runtime == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Debug("Runtime issue, Policy and ContainerInfo should not be nil")

		return fmt.Errorf("Runtime, Policy and ContainerInfo should not be nil")
	}

	_, err := s.versionTracker.Get(contextID)

	if err != nil {
		// ContextID is not found in Cache, New PU: Do create.
		return s.doCreatePU(contextID, containerInfo)
	}
	return s.doUpdatePU(contextID, containerInfo)
}

// Unsupervise removes the mapping from cache and cleans up the iptable rules. ALL
// remove operations will print errors by they don't return error. We want to force
// as much cleanup as possible to avoid stale state
func (s *iptablesSupervisor) Unsupervise(contextID string) error {

	log.WithFields(log.Fields{
		"package":   "supervisor",
		"contextID": contextID,
	}).Debug("Unsupervise the given contextID, clean the iptable rules")

	result, err := s.versionTracker.Get(contextID)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
		}).Debug("Cannot find policy version")

		return fmt.Errorf("Cannot find policy version")
	}

	cacheEntry := result.(*supervisorCacheEntry)

	appChain := s.ipu.AppChainPrefix(contextID, cacheEntry.index)
	netChain := s.ipu.NetChainPrefix(contextID, cacheEntry.index)

	// Currently processing only containers with one IP address
	ip, err := s.ipu.DefaultCacheIP(cacheEntry.ips)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
		}).Debug("Container IP address not found in cache")

		return fmt.Errorf("Container IP address not found in cache: %s", err)
	}

	s.ipu.DeletePacketTrap(appChain, netChain, ip, s.targetNetworks, s.applicationQueues, s.networkQueues)

	s.ipu.DeleteAppACLs(appChain, ip, cacheEntry.ingressACLs)

	s.ipu.DeleteNetACLs(netChain, ip, cacheEntry.egressACLs)

	s.ipu.DeleteChainRules(appChain, netChain, ip)

	s.ipu.DeleteAllContainerChains(appChain, netChain)

	s.versionTracker.Remove(contextID)

	return nil
}

// Start starts the supervisor
func (s *iptablesSupervisor) Start() error {
	log.WithFields(log.Fields{
		"package": "supervisor",
	}).Debug("Start the supervisor")

	if s.ipu.FilterMarkedPackets(s.Mark) != nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Debug("Cannot filter marked packets. Abort")

		return fmt.Errorf("Filter of marked packets was not set")
	}

	return nil
}

// Stop stops the supervisor
func (s *iptablesSupervisor) Stop() error {
	log.WithFields(log.Fields{
		"package": "supervisor",
	}).Debug("Stop the supervisor")

	// Clean any previous ACLs that we have installed
	s.CleanACL()
	return nil
}

func (s *iptablesSupervisor) doCreatePU(contextID string, containerInfo *policy.PUInfo) error {

	log.WithFields(log.Fields{
		"package":   "supervisor",
		"contextID": contextID,
	}).Debug("IPTables update for the creation of a pu")

	index := 0

	appChain := s.ipu.AppChainPrefix(contextID, index)
	netChain := s.ipu.NetChainPrefix(contextID, index)

	// Currently processing only containers with one IP address
	ipAddress, ok := containerInfo.Policy.DefaultIPAddress()

	if !ok {
		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
		}).Debug("PU IP address not found when creating a PU")

		return fmt.Errorf("PU IP address not found")
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
		}).Debug("Version the policy so that we can do hitless policy changes failed when creatin a PU")
		return err
	}

	// Configure all the ACLs
	if err := s.ipu.AddContainerChain(appChain, netChain); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"appChain":  appChain,
			"netChain":  netChain,
			"error":     err.Error(),
		}).Debug("Failed to add containerInfo chain rule when ceating a PU")

		return err
	}

	if err := s.ipu.AddChainRules(appChain, netChain, ipAddress); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"appChain":  appChain,
			"netChain":  netChain,
			"ipAddress": ipAddress,
			"error":     err.Error(),
		}).Debug("Failed to add the new chain rules when creating a PU")

		return err
	}

	if err := s.ipu.AddPacketTrap(appChain, netChain, ipAddress, s.targetNetworks, s.applicationQueues, s.networkQueues); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"appChain":  appChain,
			"netChain":  netChain,
			"ipAddress": ipAddress,
			"error":     err.Error(),
		}).Debug("Failed to add the packet trap rule when creating a PU")

		return err
	}

	if err := s.ipu.AddAppACLs(appChain, ipAddress, containerInfo.Policy.IngressACLs); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"appChain":  appChain,
			"error":     err.Error(),
		}).Debug("Failed to add the new chain app acls rules when creating a PU")

		return err
	}

	if err := s.ipu.AddNetACLs(netChain, ipAddress, containerInfo.Policy.EgressACLs); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"netChain":  netChain,
			"error":     err.Error(),
		}).Debug("Failed to add the new chain net acls rules when updating a PU")

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
		"package":   "supervisor",
		"contextID": contextID,
	}).Debug("IPTables update for the update of a pu")

	cacheEntry, err := s.versionTracker.LockedModify(contextID, add, 1)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Error finding PU in cache")

		return fmt.Errorf("Error finding PU in cache %s", err)
	}

	cachedEntry := cacheEntry.(*supervisorCacheEntry)
	newindex := cachedEntry.index
	oldindex := newindex - 1

	// Currently processing only containers with one IP address
	ipAddress, err := s.ipu.DefaultCacheIP(cachedEntry.ips)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Container IP address not found in cache when updating a PU")

		return fmt.Errorf("Container IP address not found in cache: %s", err)
	}

	appChain := s.ipu.AppChainPrefix(contextID, newindex)
	netChain := s.ipu.NetChainPrefix(contextID, newindex)

	oldAppChain := s.ipu.AppChainPrefix(contextID, oldindex)
	oldNetChain := s.ipu.NetChainPrefix(contextID, oldindex)

	//Add a new chain for this update and map all rules there
	if err := s.ipu.AddContainerChain(appChain, netChain); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"appChain":  oldAppChain,
			"netChain":  oldNetChain,
			"error":     err.Error(),
		}).Debug("Failed to add container chain rule when updating a PU")

		return err
	}

	if err := s.ipu.AddPacketTrap(appChain, netChain, ipAddress, s.targetNetworks, s.applicationQueues, s.networkQueues); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"appChain":  appChain,
			"netChain":  netChain,
			"ipAddress": ipAddress,
			"error":     err.Error(),
		}).Debug("Failed to add the packet trap rule when updating a PU")

		return err
	}

	if err := s.ipu.AddAppACLs(appChain, ipAddress, containerInfo.Policy.IngressACLs); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"appChain":  appChain,
			"error":     err.Error(),
		}).Debug("Failed to add the new chain app acls rules when updating a PU")

		return err
	}

	if err := s.ipu.AddNetACLs(netChain, ipAddress, containerInfo.Policy.EgressACLs); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"netChain":  netChain,
			"error":     err.Error(),
		}).Debug("Failed to add the new chain net acls rules when updating a PU")

		return err
	}

	// Add mapping to new chain
	if err := s.ipu.AddChainRules(appChain, netChain, ipAddress); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"appChain":  appChain,
			"netChain":  netChain,
			"ipAddress": ipAddress,
			"error":     err.Error(),
		}).Debug("Failed to add the new chain rules when updating a PU")

		return err
	}

	//Remove mapping from old chain
	if err := s.ipu.DeleteChainRules(oldAppChain, oldNetChain, ipAddress); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":     "supervisor",
			"contextID":   contextID,
			"oldAppChain": oldAppChain,
			"oldNetChain": oldNetChain,
			"ipAddress":   ipAddress,
			"error":       err.Error(),
		}).Debug("Failed to remove the old chain rules when updating a PU")

		return err
	}

	// Delete the old chain to clean up
	if err := s.ipu.DeleteAllContainerChains(oldAppChain, oldNetChain); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":     "supervisor",
			"contextID":   contextID,
			"oldAppChain": oldAppChain,
			"oldNetChain": oldNetChain,
			"error":       err.Error(),
		}).Debug("Failed to delete the old chain container rules when updating a PU")

		return err
	}

	ip, _ := containerInfo.Runtime.DefaultIPAddress()
	s.collector.CollectContainerEvent(contextID, ip, containerInfo.Runtime.Tags(), "update")

	return nil
}

// CleanACL cleans up all the ACLs that have an Trireme  Label in the mangle table
func (s *iptablesSupervisor) CleanACL() {

	log.WithFields(log.Fields{
		"package": "supervisor",
	}).Debug("Clean all ACL")

	// Clean Application Rules/Chains
	s.ipu.CleanACLs()
}

// AddExcludedIP adds an exception for the destination parameter IP, allowing all the traffic.
func (s *iptablesSupervisor) AddExcludedIP(ip string) error {

	return s.ipu.AddExclusionChainRules(ip)
}

// RemoveExcludedIP removes the exception for the destion IP given in parameter.
func (s *iptablesSupervisor) RemoveExcludedIP(ip string) error {

	return s.ipu.DeleteExclusionChainRules(ip)
}

func add(a, b interface{}) interface{} {
	entry := a.(*supervisorCacheEntry)
	entry.index += b.(int)
	return entry
}
