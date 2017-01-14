package supervisor

import (
	"fmt"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/ipsetctrl"
	"github.com/aporeto-inc/trireme/supervisor/iptablesctrl"
)

// ImplementationType defines the type of implementation
type ImplementationType int

const (
	// IPSets mandates an IPset supervisor implementation
	IPSets ImplementationType = iota
	// IPTables mandates an IPTable supervisor implementation
	IPTables
	// Remote indicates that this is a remote supervisor
)

// ModeType defines whether this is local or remote
//type ModeType int

const (
	// RemoteContainer indicates a remote supervisor
	RemoteContainer int = iota
	// LocalContainer indicates a container based supervisor
	LocalContainer
	// LocalServer indicates a Linux service
	LocalServer
)

type cacheData struct {
	version int
	ips     *policy.IPMap
	mark    string
	port    string
	impl    Implementor
}

// Config is the structure holding all information about the supervisor
type Config struct {
	//implType ImplementationType
	mode int

	versionTracker cache.DataStore
	collector      collector.EventCollector

	networkQueues     string
	applicationQueues string
	targetNetworks    []string

	Mark int

	localserverimpl    Implementor
	localcontainerimpl Implementor
}

// NewSupervisor will create a new connection supervisor that uses IPTables
// to redirect specific packets to userspace. It instantiates multiple data stores
// to maintain efficient mappings between contextID, policy and IP addresses. This
// simplifies the lookup operations at the expense of memory.
func NewSupervisor(collector collector.EventCollector, enforcerInstance enforcer.PolicyEnforcer, targetNetworks []string, mode int, implementation ImplementationType) (*Config, error) {

	if collector == nil {
		return nil, fmt.Errorf("Collector cannot be nil")
	}

	if enforcerInstance == nil {
		return nil, fmt.Errorf("Enforcer cannot be nil")
	}

	if targetNetworks == nil {
		return nil, fmt.Errorf("TargetNetworks cannot be nil")
	}

	filterQueue := enforcerInstance.GetFilterQueue()

	if filterQueue == nil {
		return nil, fmt.Errorf("Enforcer FilterQueues cannot be nil")
	}

	s := &Config{
		mode:              mode,
		localserverimpl:   nil,
		versionTracker:    cache.NewCache(),
		targetNetworks:    targetNetworks,
		collector:         collector,
		networkQueues:     strconv.Itoa(int(filterQueue.NetworkQueue)) + ":" + strconv.Itoa(int(filterQueue.NetworkQueue+filterQueue.NumberOfNetworkQueues-1)),
		applicationQueues: strconv.Itoa(int(filterQueue.ApplicationQueue)) + ":" + strconv.Itoa(int(filterQueue.ApplicationQueue+filterQueue.NumberOfApplicationQueues-1)),
		Mark:              filterQueue.MarkValue,
	}

	remote := false
	if mode == RemoteContainer {
		remote = true
	}

	var err error
	switch implementation {
	case IPSets:
		s.localserverimpl, err = ipsetctrl.NewInstance(s.networkQueues, s.applicationQueues, s.targetNetworks, s.Mark, remote, LocalServer)
		s.localcontainerimpl, err = ipsetctrl.NewInstance(s.networkQueues, s.applicationQueues, s.targetNetworks, s.Mark, remote, LocalContainer)
	default:
		s.localserverimpl, err = iptablesctrl.NewInstance(s.networkQueues, s.applicationQueues, s.targetNetworks, s.Mark, remote, LocalServer)
		s.localcontainerimpl, err = iptablesctrl.NewInstance(s.networkQueues, s.applicationQueues, s.targetNetworks, s.Mark, remote, LocalContainer)

	}
	if err != nil {
		return nil, fmt.Errorf("Unable to initialize supervisor controllers")
	}

	return s, nil
}

// Supervise creates a mapping between an IP address and the corresponding labels.
// it invokes the various handlers that process the parameter policy.
func (s *Config) Supervise(contextID string, containerInfo *policy.PUInfo) error {

	if containerInfo == nil || containerInfo.Policy == nil || containerInfo.Runtime == nil {
		return fmt.Errorf("Runtime, Policy and ContainerInfo should not be nil")
	}

	_, err := s.versionTracker.Get(contextID)

	if err != nil {
		// ContextID is not found in Cache, New PU: Do create.
		return s.doCreatePU(contextID, containerInfo)
	}

	// Context already in the cache. Just run update
	return s.doUpdatePU(contextID, containerInfo)
}

// Unsupervise removes the mapping from cache and cleans up the iptable rules. ALL
// remove operations will print errors by they don't return error. We want to force
// as much cleanup as possible to avoid stale state
func (s *Config) Unsupervise(contextID string) error {

	version, err := s.versionTracker.Get(contextID)

	if err != nil {
		return fmt.Errorf("Cannot find policy version")
	}

	cacheEntry := version.(*cacheData)

	cacheEntry.impl.DeleteRules(cacheEntry.version, contextID, cacheEntry.ips, cacheEntry.port, cacheEntry.mark)

	s.versionTracker.Remove(contextID)

	return nil
}

// Start starts the supervisor
func (s *Config) Start() error {
	log.WithFields(log.Fields{
		"package": "supervisor",
	}).Debug("Start the supervisor")

	if err := s.localserverimpl.Start(); err != nil {
		return fmt.Errorf("Filter of marked packets was not set")
	}
	if err := s.localcontainerimpl.Start(); err != nil {
		return fmt.Errorf("Filter of marked packets was not set")
	}
	return nil
}

// Stop stops the supervisor
func (s *Config) Stop() error {

	s.localserverimpl.Stop()
	s.localcontainerimpl.Stop()
	return nil
}

func (s *Config) doCreatePU(contextID string, containerInfo *policy.PUInfo) error {

	log.WithFields(log.Fields{
		"package":   "supervisor",
		"contextID": contextID,
	}).Debug("IPTables update for the creation of a pu")

	version := 0
	mark, _ := containerInfo.Runtime.Tag(cgnetcls.CgroupMarkTag)
	port, ok := containerInfo.Runtime.Tag(cgnetcls.PortTag)
	if !ok {
		port = "0"
	}
	cacheEntry := &cacheData{
		version: version,
		ips:     containerInfo.Policy.IPAddresses(),
		mark:    mark,
		port:    port,
	}
	if containerInfo.Runtime.PUType() == policy.LinuxProcessPU {
		cacheEntry.impl = s.localserverimpl
	} else {
		cacheEntry.impl = s.localcontainerimpl
	}
	// Version the policy so that we can do hitless policy changes
	if err := s.versionTracker.AddOrUpdate(contextID, cacheEntry); err != nil {
		s.Unsupervise(contextID)
		return err
	}
	if err := cacheEntry.impl.ConfigureRules(version, contextID, containerInfo); err != nil {
		s.Unsupervise(contextID)
		return err
	}

	return nil
}

// UpdatePU creates a mapping between an IP address and the corresponding labels
//and the invokes the various handlers that process all policies.
func (s *Config) doUpdatePU(contextID string, containerInfo *policy.PUInfo) error {

	cacheEntry, err := s.versionTracker.LockedModify(contextID, add, 1)

	if err != nil {
		return fmt.Errorf("Error finding PU in cache %s", err)
	}

	cachedEntry := cacheEntry.(*cacheData)

	if err := cachedEntry.impl.UpdateRules(cachedEntry.version, contextID, containerInfo); err != nil {
		s.Unsupervise(contextID)
		return fmt.Errorf("Error in updating PU implementation. PU has been terminated")
	}

	return nil
}

// AddExcludedIP adds an exception for the destination parameter IP, allowing all the traffic.
func (s *Config) AddExcludedIP(ip string) error {

	return s.localserverimpl.AddExcludedIP(ip)
}

// RemoveExcludedIP removes the exception for the destion IP given in parameter.
func (s *Config) RemoveExcludedIP(ip string) error {

	return s.localserverimpl.AddExcludedIP(ip)
}

func add(a, b interface{}) interface{} {
	entry := a.(*cacheData)
	entry.version += b.(int)
	return entry
}
