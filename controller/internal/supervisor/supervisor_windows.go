// +build windows

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/trireme-lib/controller/internal/portset"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packetprocessor"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

type cacheData struct {
	version       int
	ips           policy.ExtendedMap
	mark          string
	tcpPorts      string
	udpPorts      string
	uid           string
	containerInfo *policy.PUInfo
}

// Config is the structure holding all information about the supervisor
type Config struct {
	// mode is LocalServer or RemoteContainer
	mode constants.ModeType
	// versionTracker tracks the current version of the ACLs
	versionTracker cache.DataStore
	// impl is the packet filter implementation
	impl Implementor
	// portSetInstance is the controller of the port set
	portSetInstance portset.PortSet
	// collector is the stats collector implementation
	collector collector.EventCollector
	// filterQueue is the filterqueue parameters
	filterQueue *fqconfig.FilterQueue
	// excludeIPs are the IPs that must be always excluded
	excludedIPs []string
	// triremeNetworks are the target networks where Trireme is implemented
	triremeNetworks []string

	sync.Mutex
}

// NewSupervisor will create a new connection supervisor that uses IPTables
// to redirect specific packets to userspace. It instantiates multiple data stores
// to maintain efficient mappings between contextID, policy and IP addresses. This
// simplifies the lookup operations at the expense of memory.
func NewSupervisor(collector collector.EventCollector, enforcerInstance enforcer.Enforcer, mode constants.ModeType, networks []string, p packetprocessor.PacketProcessor) (*Config, error) {

	if collector == nil || enforcerInstance == nil {
		return nil, errors.New("Invalid parameters")
	}

	filterQueue := enforcerInstance.GetFilterQueue()
	if filterQueue == nil {
		return nil, errors.New("enforcer filter queues cannot be nil")
	}

	portSetInstance := enforcerInstance.GetPortSetInstance()
	if mode != constants.RemoteContainer && portSetInstance == nil {
		return nil, errors.New("portSetInstance cannot be nil")
	}

	// TODO :: New Driver instance when we support runtime config on driver
	// impl, err := iptablesctrl.NewInstance(filterQueue, mode, portSetInstance)
	// if err != nil {
	// 	return nil, fmt.Errorf("unable to initialize supervisor controllers: %s", err)
	// }

	return &Config{
		mode:            mode,
		impl:            nil,
		versionTracker:  cache.NewCache("SupVersionTracker"),
		collector:       collector,
		filterQueue:     filterQueue,
		excludedIPs:     []string{},
		triremeNetworks: networks,
		portSetInstance: portSetInstance,
	}, nil
}

// Supervise creates a mapping between an IP address and the corresponding labels.
// it invokes the various handlers that process the parameter policy.
func (s *Config) Supervise(contextID string, pu *policy.PUInfo) error {
	if pu == nil || pu.Policy == nil || pu.Runtime == nil {
		return errors.New("Invalid PU or policy info")
	}

	_, err := s.versionTracker.Get(contextID)
	if err != nil {
		// ContextID is not found in Cache, New PU: Do create.
		return s.doCreatePU(contextID, pu)
	}

	// Context already in the cache. Just run update
	return s.doUpdatePU(contextID, pu)
}

// Unsupervise removes the mapping from cache and cleans up the iptable rules. ALL
// remove operations will print errors by they don't return error. We want to force
// as much cleanup as possible to avoid stale state
func (s *Config) Unsupervise(contextID string) error {

	_, err := s.versionTracker.Get(contextID)
	if err != nil {
		return fmt.Errorf("cannot find policy version: %s", err)
	}

	//cfg := data.(*cacheData)
	//port := cfg.containerInfo.Runtime.Options().ProxyPort

	// Delete rules not called on windows implementation since the Driver we use today does not allow runtime config
	// TODO ::: Reenable when we have driver support
	/* if err := s.impl.DeleteRules(cfg.version, contextID, cfg.tcpPorts, cfg.udpPorts, cfg.mark, cfg.uid, port); err != nil {
		zap.L().Warn("Some rules were not deleted during unsupervise", zap.Error(err))
	} */

	if err := s.versionTracker.Remove(contextID); err != nil {
		zap.L().Warn("Failed to clean the rule version cache", zap.Error(err))
	}

	return nil
}

// Run starts the supervisor
func (s *Config) Run(ctx context.Context) error {

	/* if err := s.impl.Run(ctx); err != nil {
		return fmt.Errorf("unable to start the implementer: %s", err)
	} */

	//TODO :: Impl is null since driver does not support
	/* 	s.Lock()
	   	defer s.Unlock()
		   return s.impl.SetTargetNetworks([]string{}, s.triremeNetworks) */
	return nil
}

// CleanUp implements the cleanup interface
func (s *Config) CleanUp() error {
	// TODO :: Cleanup driver nothing done here since we don't init driver here
	return nil
	/* s.Lock()
	defer s.Unlock()

	return s.impl.CleanUp() */
}

// SetTargetNetworks sets the target networks of the supervisor
func (s *Config) SetTargetNetworks(networks []string) error {

	s.Lock()
	defer s.Unlock()

	// If there are no target networks, capture all traffic
	if len(networks) == 0 {
		networks = []string{"0.0.0.0/1", "128.0.0.0/1"}
	}
	s.triremeNetworks = networks
	//TODO:: Runtime API required
	//return s.impl.SetTargetNetworks(s.triremeNetworks, networks)
	return nil
}

func (s *Config) doCreatePU(contextID string, pu *policy.PUInfo) error {

	s.Lock()
	defer s.Unlock()

	tcpPorts, udpPorts := common.ConvertServicesToProtocolPortList(pu.Runtime.Options().Services)
	c := &cacheData{
		version:       0,
		ips:           pu.Policy.IPAddresses(),
		mark:          pu.Runtime.Options().CgroupMark,
		tcpPorts:      tcpPorts,
		udpPorts:      udpPorts,
		uid:           pu.Runtime.Options().UserID,
		containerInfo: pu,
	}

	// Version the policy so that we can do hitless policy changes
	s.versionTracker.AddOrUpdate(contextID, c)
	// TODO :: NO runtime config on driver right now
	// Configure the rules
	/* if err := s.impl.ConfigureRules(c.version, contextID, pu); err != nil {
		// Revert what you can since we have an error - it will fail most likely
		s.Unsupervise(contextID) // nolint
		return err
	} */

	return nil
}

// UpdatePU creates a mapping between an IP address and the corresponding labels
//and the invokes the various handlers that process all policies.
func (s *Config) doUpdatePU(contextID string, pu *policy.PUInfo) error {

	s.Lock()
	defer s.Unlock()
	_, err := s.versionTracker.LockedModify(contextID, revert, 1)
	if err != nil {
		return fmt.Errorf("unable to find pu %s in cache: %s", contextID, err)
	}
	// TODO :: TODOD runtime rule modification
	/* data, err := s.versionTracker.LockedModify(contextID, revert, 1)
	if err != nil {
		return fmt.Errorf("unable to find pu %s in cache: %s", contextID, err)
	}

	c := data.(*cacheData)
	if err := s.impl.UpdateRules(c.version, contextID, pu, c.containerInfo); err != nil {
		// Try to clean up, even though this is fatal and it will most likely fail
		s.Unsupervise(contextID) // nolint
		return err
	} */

	return nil
}

func revert(a, b interface{}) interface{} {
	entry := a.(*cacheData)
	entry.version = entry.version ^ 1
	return entry
}
