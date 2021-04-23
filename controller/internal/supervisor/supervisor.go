package supervisor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/supervisor/iptablesctrl"
	supervisornoop "go.aporeto.io/enforcerd/trireme-lib/controller/internal/supervisor/noop"
	provider "go.aporeto.io/enforcerd/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/counters"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/enforcerd/trireme-lib/controller/runtime"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

type cacheData struct {
	version       int
	ips           policy.ExtendedMap
	mark          string
	tcpPorts      string
	udpPorts      string
	username      string
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
	// collector is the stats collector implementation
	collector collector.EventCollector
	// filterQueue is the filterqueue parameters
	filterQueue fqconfig.FilterQueue
	// cfg is the mutable configuration
	cfg *runtime.Configuration
	sync.Mutex
}

// NewSupervisor will create a new connection supervisor that uses IPTables
// to redirect specific packets to userspace. It instantiates multiple data stores
// to maintain efficient mappings between contextID, policy and IP addresses. This
// simplifies the lookup operations at the expense of memory.
func NewSupervisor(
	collector collector.EventCollector,
	enforcerInstance enforcer.Enforcer,
	mode constants.ModeType,
	cfg *runtime.Configuration,
	ipv6Enabled bool,
	iptablesLockfile string,
) (Supervisor, error) {

	// for certain modes we do not want to launch a supervisor at all, so we are going to launch a noop supervisor
	// like we do for the supervisor proxy
	if mode == constants.RemoteContainerEnvoyAuthorizer {
		return supervisornoop.NewNoopSupervisor(), nil
	}

	if collector == nil || enforcerInstance == nil {
		return nil, errors.New("Invalid parameters")
	}

	filterQueue := enforcerInstance.GetFilterQueue()
	if filterQueue == nil {
		return nil, errors.New("enforcer filter queues cannot be nil")
	}

	bpf := enforcerInstance.GetBPFObject()
	serviceMeshType := enforcerInstance.GetServiceMeshType()
	impl, err := iptablesctrl.NewInstance(filterQueue, mode, ipv6Enabled, bpf, iptablesLockfile, serviceMeshType)

	if err != nil {
		return nil, fmt.Errorf("unable to initialize supervisor controllers: %s", err)
	}

	return &Config{
		mode:           mode,
		impl:           impl,
		versionTracker: cache.NewCache("SupVersionTracker"),
		collector:      collector,
		filterQueue:    filterQueue,
		cfg:            cfg,
	}, nil
}

// Run starts the supervisor
func (s *Config) Run(ctx context.Context) error {

	s.Lock()
	defer s.Unlock()

	if err := s.impl.Run(ctx); err != nil {
		return fmt.Errorf("unable to start the implementer: %s", err)
	}

	if err := s.impl.SetTargetNetworks(s.cfg); err != nil {
		return err
	}

	if err := s.impl.CreateCustomRulesChain(); err != nil {
		return err
	}

	return nil
}

// Supervise creates a mapping between an IP address and the corresponding labels.
// it invokes the various handlers that process the parameter policy.
func (s *Config) Supervise(contextID string, pu *policy.PUInfo) error {

	if pu == nil || pu.Policy == nil || pu.Runtime == nil {
		return errors.New("Invalid PU or policy info")
	}

	if _, err := s.versionTracker.Get(contextID); err != nil {
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
	s.Lock()
	defer s.Unlock()

	data, err := s.versionTracker.Get(contextID)
	if err != nil {
		return fmt.Errorf("cannot find policy version: %s", err)
	}

	cfg := data.(*cacheData)

	// TODO (varks): Similar to configureRules and UpdateRules, DeleteRules should take
	// only contextID and *policy.PUInfo as function parameters.
	if err := s.impl.DeleteRules(cfg.version, contextID, cfg.tcpPorts, cfg.udpPorts, cfg.mark, cfg.username, cfg.containerInfo); err != nil {
		zap.L().Warn("Some rules were not deleted during unsupervise", zap.Error(err))
	}

	if err := s.versionTracker.Remove(contextID); err != nil {
		zap.L().Warn("Failed to clean the rule version cache", zap.Error(err))
	}

	ipsetmanager.V4().RemoveExternalNets(contextID)
	ipsetmanager.V6().RemoveExternalNets(contextID)

	return nil
}

// CleanUp implements the cleanup interface
func (s *Config) CleanUp() error {
	s.Lock()
	defer s.Unlock()

	return s.impl.CleanUp()
}

// SetTargetNetworks sets the target networks of the supervisor
func (s *Config) SetTargetNetworks(cfg *runtime.Configuration) error {

	s.Lock()
	defer s.Unlock()

	s.cfg = cfg.DeepCopy()
	return s.impl.SetTargetNetworks(cfg)
}

// ACLProvider returns the ACL provider used by the supervisor that can be
// shared with other entities.
func (s *Config) ACLProvider() []provider.IptablesProvider {
	return s.impl.ACLProvider()
}

func (s *Config) doCreatePU(contextID string, pu *policy.PUInfo) error {

	s.Lock()

	tcpPorts, udpPorts := common.ConvertServicesToProtocolPortList(pu.Runtime.Options().Services)
	c := &cacheData{
		version:       0,
		ips:           pu.Policy.IPAddresses(),
		mark:          pu.Runtime.Options().CgroupMark,
		tcpPorts:      tcpPorts,
		udpPorts:      udpPorts,
		username:      pu.Runtime.Options().UserID,
		containerInfo: pu,
	}

	// Version the policy so that we can do hitless policy changes
	s.versionTracker.AddOrUpdate(contextID, c)

	var iprules policy.IPRuleList

	iprules = append(iprules, pu.Policy.ApplicationACLs()...)
	iprules = append(iprules, pu.Policy.NetworkACLs()...)

	if err := ipsetmanager.V4().RegisterExternalNets(contextID, iprules); err != nil {
		s.Unlock()
		zap.L().Error("Error creating ipsets for external networks", zap.Error(err))
		return err
	}

	if err := ipsetmanager.V6().RegisterExternalNets(contextID, iprules); err != nil {
		s.Unlock()
		zap.L().Error("Error creating ipsets for external networks", zap.Error(err))
		return err
	}

	// Configure the rules
	if err := s.impl.ConfigureRules(c.version, contextID, pu); err != nil {
		// Revert what you can since we have an error - it will fail most likely
		zap.L().Error("ConfigureRules Failed with error", zap.Error(err))
		s.Unlock()
		s.Unsupervise(contextID) // nolint
		return err
	}

	s.Unlock()

	return nil
}

// UpdatePU creates a mapping between an IP address and the corresponding labels
//and the invokes the various handlers that process all policies.
func (s *Config) doUpdatePU(contextID string, pu *policy.PUInfo) error {

	s.Lock()

	data, err := s.versionTracker.Get(contextID)
	if err != nil {
		s.Unlock()
		return fmt.Errorf("unable to find pu %s in cache: %s", contextID, err)
	}

	var iprules policy.IPRuleList

	iprules = append(iprules, pu.Policy.ApplicationACLs()...)
	iprules = append(iprules, pu.Policy.NetworkACLs()...)

	if err := ipsetmanager.V4().RegisterExternalNets(contextID, iprules); err != nil {
		s.Unlock()
		zap.L().Error("Error creating ipsets for external networks", zap.Error(err))
		return err
	}

	if err := ipsetmanager.V6().RegisterExternalNets(contextID, iprules); err != nil {
		s.Unlock()
		zap.L().Error("Error creating ipsets for external networks", zap.Error(err))
		return err
	}

	c := data.(*cacheData)

	if err := s.impl.UpdateRules(c.version^1, contextID, pu, c.containerInfo); err != nil {
		zap.L().Error("Update rules failed with error...Reconfiguring the system", zap.Error(err))
		counters.IncrementCounter(counters.ErrIPTablesReset)
		s.Unlock()

		s.Unsupervise(contextID)    //nolint
		s.CleanUp()                 //nolint
		s.Run(context.Background()) //nolint
		return s.Supervise(contextID, pu)
	}

	c.version ^= 1

	// Updated the policy in the cached processing unit.
	c.containerInfo.Policy = pu.Policy

	ipsetmanager.V4().DestroyUnusedIPsets()
	ipsetmanager.V6().DestroyUnusedIPsets()

	s.Unlock()
	return nil
}

// EnableIPTablesPacketTracing enables ip tables packet tracing
func (s *Config) EnableIPTablesPacketTracing(ctx context.Context, contextID string, interval time.Duration) error {

	data, err := s.versionTracker.Get(contextID)
	if err != nil {
		return fmt.Errorf("cannot find policy version: %s", err)
	}

	cfg := data.(*cacheData)
	iptablesRules := debugRules(cfg, s.mode)
	ipts := s.impl.ACLProvider()

	for _, ipt := range ipts {
		for _, rule := range iptablesRules {
			if err := ipt.Insert(rule[0], rule[1], 1, rule[2:]...); err != nil {
				zap.L().Error("Unable to install rule", zap.Error(err))
			}
		}

		// anonymous go func to flush debug iptables after interval
		go func(ipt provider.IptablesProvider) {
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(interval):
					for _, rule := range iptablesRules {
						if err := ipt.Delete(rule[0], rule[1], rule[2:]...); err != nil {
							zap.L().Debug("Unable to delete trace rules", zap.Error(err))
						}
					}
				}
			}
		}(ipt)
	}
	return nil
}

func debugRules(data *cacheData, mode constants.ModeType) [][]string {
	iptables := [][]string{}
	if mode == constants.RemoteContainer {
		iptables = append(iptables, [][]string{
			{
				"raw",
				"PREROUTING",
				"-j", "TRACE",
			},
			{
				"raw",
				"OUTPUT",
				"-j", "TRACE",
			},
		}...)
	} else {
		if data.tcpPorts != "0" {
			iptables = append(iptables,
				[][]string{
					{
						"raw",
						"PREROUTING",
						"-p", "tcp",
						"--match", "multiport",
						"--destination-ports", data.tcpPorts,
						"-j", "TRACE",
					},
					{
						"raw",
						"OUTPUT",
						"--match", "multiport",
						"--source-ports", data.tcpPorts,
						"-j", "TRACE",
					},
				}...,
			)

		} else {
			iptables = append(iptables, [][]string{
				{
					"raw",
					"PREROUTING",
					"-p", "tcp",
					"-j", "TRACE",
				},
				{
					"raw",
					"OUTPUT",
					"-m", "cgroup",
					"--cgroup", data.mark,
					"-j", "TRACE",
				},
			}...)
		}
		if data.udpPorts != "0" {
			iptables = append(iptables, [][]string{
				{
					"raw",
					"PREROUTING",
					"-p", "udp",
					"--match", "multiport",
					"--destination-ports", data.udpPorts,
					"-j", "TRACE",
				},
				{
					"raw",
					"OUTPUT",
					"--match", "multiport",
					"--source-ports", data.tcpPorts,
					"-j", "TRACE",
				},
			}...)
		} else {
			iptables = append(iptables,
				[][]string{
					{
						"raw",
						"PREROUTING",
						"-p", "tcp",
						"-j", "TRACE",
					},
					{
						"raw",
						"OUTPUT",
						"-m", "cgroup",
						"--cgroup", data.mark,
						"-j", "TRACE",
					},
				}...)
		}
	}
	return iptables
}
