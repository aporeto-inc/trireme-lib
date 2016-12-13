package supervisor

import (
	"fmt"
	"strconv"

	"github.com/aporeto-inc/trireme/cache"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/iptablesutils"
)

const (
	triremeSet = "TriremeSet"
)

type ipsetSupervisor struct {
	versionTracker    cache.DataStore
	ipu               iptablesutils.IpsetUtils
	collector         collector.EventCollector
	networkQueues     string
	applicationQueues string
	targetNetworks    []string
}

// NewIPSetSupervisor returns a new implementation of the Supervisor based on IPSets.
func NewIPSetSupervisor(collector collector.EventCollector, enforcer enforcer.PolicyEnforcer, ipsetUtils iptablesutils.IpsetUtils, targetNetworks []string) (Supervisor, error) {
	if collector == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Debug("Collector cannot be nil in NewIPSetSupervisor")
		return nil, fmt.Errorf("Collector cannot be nil")
	}

	if enforcer == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Debug("Enforcer cannot be nil in NewIPSetSupervisor")
		return nil, fmt.Errorf("Enforcer cannot be nil")
	}

	if ipsetUtils == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Debug("IpsetUtils cannot be nil in NewIPSetSupervisor")

		return nil, fmt.Errorf("IpsetProvider cannot be nil")
	}

	if targetNetworks == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Debug("TargetNetworks cannot be nil in NewIPSetSupervisor")

		return nil, fmt.Errorf("TargetNetworks cannot be nil")
	}

	filterQueue := enforcer.GetFilterQueue()

	if filterQueue == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Debug("Enforcer FilterQueues cannot be nil in NewIPSetSupervisor")

		return nil, fmt.Errorf("Enforcer FilterQueues cannot be nil")
	}

	s := &ipsetSupervisor{
		ipu:               ipsetUtils,
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

	log.WithFields(log.Fields{
		"package":   "supervisor",
		"contextID": contextID,
	}).Debug("PU ContextID Already exist in Cache. Updating.")

	return s.doUpdatePU(contextID, containerInfo)
}

func (s *ipsetSupervisor) Unsupervise(contextID string) error {

	log.WithFields(log.Fields{
		"package":   "supervisor",
		"contextID": contextID,
	}).Debug("Unsupervise PU")

	result, err := s.versionTracker.Get(contextID)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
		}).Debug("Cannot find policy version in cache")
		return fmt.Errorf("Cannot find policy version in cache")
	}

	cacheEntry := result.(*supervisorCacheEntry)

	appSet := s.ipu.AppChainPrefix(contextID, cacheEntry.index)
	netSet := s.ipu.NetChainPrefix(contextID, cacheEntry.index)

	// Currently processing only containers with one IP address
	ip, err := s.ipu.DefaultCacheIP(cacheEntry.ips)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
		}).Debug("PU IP address not found in cache")

		return fmt.Errorf("PU IP address not found in cache: %s", err)
	}

	s.ipu.DeleteAppSetRule(appSet, ip)

	s.ipu.DeleteNetSetRule(netSet, ip)

	s.ipu.DeleteSet(appSet)

	s.ipu.DeleteSet(netSet)

	s.versionTracker.Remove(contextID)

	return nil
}

func (s *ipsetSupervisor) Start() error {
	if err := s.createInitialIPSet(); err != nil {
		return err
	}
	if err := s.ipu.SetupTrapRules(triremeSet, s.networkQueues, s.applicationQueues); err != nil {
		return err
	}
	return nil
}

func (s *ipsetSupervisor) Stop() error {
	s.cleanACLs()
	return nil
}

func (s *ipsetSupervisor) doAddSets(contextID string, appSet string, netSet string, appACLs []policy.IPRule, netACLs []policy.IPRule, ip string) error {

	if err := s.ipu.CreateACLSets(appSet, appACLs); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Failed to create the AppSet IPSet.")
		return err
	}

	if err := s.ipu.CreateACLSets(netSet, netACLs); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Failed to create the NetSet IPSet.")
		return err
	}

	if err := s.ipu.AddAppSetRule(appSet, ip); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"ipAddress": ip,
			"error":     err.Error(),
		}).Debug("Failed to add a rule that matches the AppSet IPSet")
		return err
	}

	if err := s.ipu.AddNetSetRule(netSet, ip); err != nil {
		s.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Failed to add a rule that matches the AppSet IPSet")

		return err
	}
	return nil
}

func (s *ipsetSupervisor) doCreatePU(contextID string, containerInfo *policy.PUInfo) error {

	log.WithFields(log.Fields{
		"package":   "supervisor",
		"contextID": contextID,
	}).Debug("PU Creation")

	index := 0

	appSet := s.ipu.AppChainPrefix(contextID, index)
	netSet := s.ipu.NetChainPrefix(contextID, index)

	// Currently processing only containers with one IP address
	ipAddress, ok := containerInfo.Policy.DefaultIPAddress()

	if !ok {
		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
		}).Debug("Default Container IP address not found in Policy")

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
		}).Debug("Error Versioning the policy")
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
	}).Debug("PU Supervisor Update")

	cacheEntry, err := s.versionTracker.LockedModify(contextID, add, 1)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "supervisor",
			"contextID": contextID,
			"error":     err.Error(),
		}).Error("Error finding PU in cache")
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
		}).Debug("PU IP address not found in cache when updating a PU")

		return fmt.Errorf("PU IP address not found in cache: %s", err)
	}

	appSet := s.ipu.AppChainPrefix(contextID, newindex)
	netSet := s.ipu.NetChainPrefix(contextID, newindex)

	oldAppSet := s.ipu.AppChainPrefix(contextID, oldindex)
	oldNetSet := s.ipu.NetChainPrefix(contextID, oldindex)

	if err := s.doAddSets(contextID, appSet, netSet, containerInfo.Policy.IngressACLs, containerInfo.Policy.EgressACLs, ipAddress); err != nil {
		return err
	}

	s.ipu.DeleteAppSetRule(oldAppSet, ipAddress)

	s.ipu.DeleteNetSetRule(oldNetSet, ipAddress)

	s.ipu.DeleteSet(oldAppSet)

	s.ipu.DeleteSet(oldNetSet)

	ip, _ := containerInfo.Runtime.DefaultIPAddress()
	s.collector.CollectContainerEvent(contextID, ip, containerInfo.Runtime.Tags(), "update")

	return nil
}

func (s *ipsetSupervisor) createInitialIPSet() error {

	return s.ipu.SetupIpset(triremeSet, s.targetNetworks)
}

func (s *ipsetSupervisor) cleanACLs() error {
	log.WithFields(log.Fields{
		"package": "supervisor",
	}).Debug("Cleaning all IPTables")

	// Clean Application Rules/Chains
	s.ipu.CleanACLs()

	s.ipu.CleanIPSets()

	return nil
}

func (s *ipsetSupervisor) AddExcludedIP(ip string) error {

	return s.ipu.AddIpsetOption(ip)
}

func (s *ipsetSupervisor) RemoveExcludedIP(ip string) error {

	return s.ipu.DeleteIpsetOption(ip)
}
