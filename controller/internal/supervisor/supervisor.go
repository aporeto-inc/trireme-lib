package supervisor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor/iptablesctrl"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packetprocessor"
	"go.aporeto.io/trireme-lib/controller/runtime"
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
	filterQueue *fqconfig.FilterQueue
	// service is an external packet service
	service packetprocessor.PacketProcessor
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
	p packetprocessor.PacketProcessor,
) (Supervisor, error) {

	if collector == nil || enforcerInstance == nil {
		return nil, errors.New("Invalid parameters")
	}

	filterQueue := enforcerInstance.GetFilterQueue()
	if filterQueue == nil {
		return nil, errors.New("enforcer filter queues cannot be nil")
	}

	impl, err := iptablesctrl.NewInstance(filterQueue, mode, cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize supervisor controllers: %s", err)
	}

	return &Config{
		mode:           mode,
		impl:           impl,
		versionTracker: cache.NewCache("SupVersionTracker"),
		collector:      collector,
		filterQueue:    filterQueue,
		service:        p,
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

	if s.service != nil {
		s.service.Initialize(s.filterQueue, s.impl.ACLProvider())
	}

	return nil
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
	s.Lock()
	defer s.Unlock()

	data, err := s.versionTracker.Get(contextID)
	if err != nil {
		return fmt.Errorf("cannot find policy version: %s", err)
	}

	cfg := data.(*cacheData)
	port := cfg.containerInfo.Policy.ServicesListeningPort()

	// If local server, delete pu specific chains in Trireme/NetworkSvc/Hostmode chains.
	puType := cfg.containerInfo.Runtime.PUType()

	// TODO (varks): Similar to configureRules and UpdateRules, DeleteRules should take
	// only contextID and *policy.PUInfo as function parameters.
	if err := s.impl.DeleteRules(cfg.version, contextID, cfg.tcpPorts, cfg.udpPorts, cfg.mark, cfg.username, port, puType); err != nil {
		zap.L().Warn("Some rules were not deleted during unsupervise", zap.Error(err))
	}

	if err := s.versionTracker.Remove(contextID); err != nil {
		zap.L().Warn("Failed to clean the rule version cache", zap.Error(err))
	}

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

	return s.impl.SetTargetNetworks(cfg)
}

// ACLProvider returns the ACL provider used by the supervisor that can be
// shared with other entities.
func (s *Config) ACLProvider() provider.IptablesProvider {
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

	// Configure the rules
	if err := s.impl.ConfigureRules(c.version, contextID, pu); err != nil {
		// Revert what you can since we have an error - it will fail most likely
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

	data, err := s.versionTracker.LockedModify(contextID, revert, 1)
	if err != nil {
		return fmt.Errorf("unable to find pu %s in cache: %s", contextID, err)
	}

	c := data.(*cacheData)
	if err := s.impl.UpdateRules(c.version, contextID, pu, c.containerInfo); err != nil {
		// Try to clean up, even though this is fatal and it will most likely fail
		s.Unlock()
		s.Unsupervise(contextID) // nolint
		return err
	}

	// Updated the policy in the cached processing unit.
	c.containerInfo.Policy = pu.Policy

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
	ipt := s.impl.ACLProvider()

	for _, rule := range iptablesRules {
		if err := ipt.Insert(rule[0], rule[1], 1, rule[2:]...); err != nil {
			zap.L().Error("Unable to install rule", zap.Error(err))
		}
	}

	// anonymous go func to flush debug iptables after interval
	go func() {
		for {
			select {
			case <-ctx.Done():
			case <-time.After(interval):
				for _, rule := range iptablesRules {
					if err := ipt.Delete(rule[0], rule[1], rule[2:]...); err != nil {
						zap.L().Debug("Unable to delete trace rules", zap.Error(err))
					}
				}
			}
		}
	}()
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

func revert(a, b interface{}) interface{} {
	entry := a.(*cacheData)
	entry.version = entry.version ^ 1
	return entry
}
