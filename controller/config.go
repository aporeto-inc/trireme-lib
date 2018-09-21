package controller

import (
	"fmt"
	"sync"
	"time"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/proxy"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor/proxy"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packetprocessor"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/utils/allocator"
	"go.uber.org/zap"
)

// config specifies all configurations accepted by trireme to start.
type config struct {
	// Required Parameters.
	serverID string

	// External Interface implementations that we allow to plugin to components.
	collector collector.EventCollector
	service   packetprocessor.PacketProcessor
	secret    secrets.Secrets

	// Configurations for fine tuning internal components.
	mode                   constants.ModeType
	fq                     *fqconfig.FilterQueue
	linuxProcess           bool
	mutualAuth             bool
	packetLogs             bool
	validity               time.Duration
	procMountPoint         string
	externalIPcacheTimeout time.Duration
	targetNetworks         []string
	proxyPort              int
}

// Option is provided using functional arguments.
type Option func(*config)

// OptionCollector is an option to provide an external collector implementation.
func OptionCollector(c collector.EventCollector) Option {
	return func(cfg *config) {
		cfg.collector = c
	}
}

// OptionDatapathService is an option to provide an external datapath service implementation.
func OptionDatapathService(s packetprocessor.PacketProcessor) Option {
	return func(cfg *config) {
		cfg.service = s
	}
}

// OptionSecret is an option to provide an external datapath service implementation.
func OptionSecret(s secrets.Secrets) Option {
	return func(cfg *config) {
		cfg.secret = s
	}
}

// OptionEnforceLinuxProcess is an option to request support for linux process support.
func OptionEnforceLinuxProcess() Option {
	return func(cfg *config) {
		cfg.linuxProcess = true
	}
}

// OptionEnforceFqConfig is an option to override filter queues.
func OptionEnforceFqConfig(f *fqconfig.FilterQueue) Option {
	return func(cfg *config) {
		cfg.fq = f
	}
}

// OptionDisableMutualAuth is an option to disable MutualAuth (enabled by default)
func OptionDisableMutualAuth() Option {
	return func(cfg *config) {
		cfg.mutualAuth = false
	}
}

// OptionTargetNetworks is an option to provide target network configuration.
func OptionTargetNetworks(n []string) Option {
	return func(cfg *config) {
		cfg.targetNetworks = n
	}
}

// OptionApplicationProxyPort is an option provide starting proxy port for application proxy
func OptionApplicationProxyPort(proxyPort int) Option {
	return func(cfg *config) {
		cfg.proxyPort = proxyPort
	}
}

// OptionProcMountPoint is an option to provide proc mount point.
func OptionProcMountPoint(p string) Option {
	return func(cfg *config) {
		cfg.procMountPoint = p
	}
}

// OptionPacketLogs is an option to enable packet level logging.
func OptionPacketLogs() Option {
	return func(cfg *config) {
		cfg.packetLogs = true
	}
}

func (t *trireme) newEnforcers() error {
	zap.L().Debug("LinuxProcessSupport", zap.Bool("Status", t.config.linuxProcess))
	var err error
	if t.config.linuxProcess {
		t.enforcers[constants.LocalServer], err = enforcer.New(
			t.config.mutualAuth,
			t.config.fq,
			t.config.collector,
			t.config.service,
			t.config.secret,
			t.config.serverID,
			t.config.validity,
			constants.LocalServer,
			t.config.procMountPoint,
			t.config.externalIPcacheTimeout,
			t.config.packetLogs,
			t.config.targetNetworks,
		)
		if err != nil {
			return fmt.Errorf("Failed to initialize enforcer: %s ", err)
		}
	}

	zap.L().Debug("TriremeMode", zap.Int("Status", int(t.config.mode)))
	if t.config.mode == constants.RemoteContainer {
		t.enforcers[constants.RemoteContainer] = enforcerproxy.NewProxyEnforcer(
			t.config.mutualAuth,
			t.config.fq,
			t.config.collector,
			t.config.service,
			t.config.secret,
			t.config.serverID,
			t.config.validity,
			t.rpchdl,
			"enforce",
			t.config.procMountPoint,
			t.config.externalIPcacheTimeout,
			t.config.packetLogs,
			t.config.targetNetworks,
		)
	}

	zap.L().Debug("TriremeMode", zap.Int("Status", int(t.config.mode)))
	if t.config.mode == constants.Sidecar {
		t.enforcers[constants.Sidecar], err = enforcer.New(
			t.config.mutualAuth,
			t.config.fq,
			t.config.collector,
			t.config.service,
			t.config.secret,
			t.config.serverID,
			t.config.validity,
			constants.Sidecar,
			t.config.procMountPoint,
			t.config.externalIPcacheTimeout,
			t.config.packetLogs,
			t.config.targetNetworks,
		)
		if err != nil {
			return fmt.Errorf("Failed to initialize sidecar enforcer: %s ", err)
		}
	}

	return nil
}

func (t *trireme) newSupervisors() error {

	if t.config.linuxProcess {
		sup, err := supervisor.NewSupervisor(
			t.config.collector,
			t.enforcers[constants.LocalServer],
			constants.LocalServer,
			t.config.targetNetworks,
			t.config.service,
		)
		if err != nil {
			return fmt.Errorf("Could Not create process supervisor :: received error %v", err)
		}
		t.supervisors[constants.LocalServer] = sup
	}

	if t.config.mode == constants.RemoteContainer {
		s, err := supervisorproxy.NewProxySupervisor(
			t.config.collector,
			t.enforcers[constants.RemoteContainer],
			t.rpchdl,
		)
		if err != nil {
			zap.L().Error("Unable to create proxy Supervisor:: Returned Error ", zap.Error(err))
			return nil
		}
		t.supervisors[constants.RemoteContainer] = s
	}

	if t.config.mode == constants.Sidecar {
		s, err := supervisor.NewSupervisor(
			t.config.collector,
			t.enforcers[constants.Sidecar],
			constants.Sidecar,
			t.config.targetNetworks,
			t.config.service,
		)
		if err != nil {
			return fmt.Errorf("Could Not create process sidecar supervisor :: received error %v", err)
		}
		t.supervisors[constants.Sidecar] = s
	}

	return nil
}

// newTrireme returns a reference to the trireme object based on the parameter subelements.
func newTrireme(c *config) TriremeController {

	var err error

	t := &trireme{
		config:               c,
		port:                 allocator.New(c.proxyPort, 100),
		rpchdl:               rpcwrapper.NewRPCWrapper(),
		enforcers:            map[constants.ModeType]enforcer.Enforcer{},
		supervisors:          map[constants.ModeType]supervisor.Supervisor{},
		puTypeToEnforcerType: map[common.PUType]constants.ModeType{},
		locks:                sync.Map{},
	}

	zap.L().Debug("Creating Enforcers")
	if err = t.newEnforcers(); err != nil {
		zap.L().Error("Unable to create datapath enforcers", zap.Error(err))
		return nil
	}

	zap.L().Debug("Creating Supervisors")
	if err = t.newSupervisors(); err != nil {
		zap.L().Error("Unable to start datapath supervisor", zap.Error(err))
		return nil
	}

	if c.linuxProcess {
		t.puTypeToEnforcerType[common.LinuxProcessPU] = constants.LocalServer
		t.puTypeToEnforcerType[common.UIDLoginPU] = constants.LocalServer
	}

	if t.config.mode == constants.RemoteContainer {
		t.puTypeToEnforcerType[common.ContainerPU] = constants.RemoteContainer
		t.puTypeToEnforcerType[common.KubernetesPU] = constants.RemoteContainer
	}

	if t.config.mode == constants.Sidecar {
		t.puTypeToEnforcerType[common.ContainerPU] = constants.Sidecar
	}

	return t
}
