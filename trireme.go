package trireme

import (
	"fmt"
	"time"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/packetprocessor"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/internal/monitor"
	"go.uber.org/zap"
)

// config specifies all configurations accepted by trireme to start.
type config struct {
	// Required Parameters.
	serverID string

	// External Interface implementations that we allow to plugin to components.
	collector collector.EventCollector
	resolver  PolicyResolver
	service   packetprocessor.PacketProcessor
	secret    secrets.Secrets

	// Configurations for fine tuning internal components.
	monitors               *monitor.Config
	mode                   constants.ModeType
	fq                     *fqconfig.FilterQueue
	linuxProcess           bool
	mutualAuth             bool
	packetLogs             bool
	validity               time.Duration
	procMountPoint         string
	externalIPcacheTimeout time.Duration
	targetNetworks         []string
}

// Option is provided using functional arguments.
type Option func(*config)

// OptionCollector is an option to provide an external collector implementation.
func OptionCollector(c collector.EventCollector) Option {
	return func(cfg *config) {
		cfg.collector = c
	}
}

// OptionPolicyResolver is an option to provide an external policy resolver implementation.
func OptionPolicyResolver(r PolicyResolver) Option {
	return func(cfg *config) {
		cfg.resolver = r
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

// OptionMonitors is an option to provide configurations for monitors.
func OptionMonitors(m *monitor.Config) Option {
	return func(cfg *config) {
		cfg.monitors = m
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

// New returns a trireme interface implementation based on configuration provided.
func New(serverID string, opts ...Option) Trireme {

	c := &config{
		serverID:               serverID,
		collector:              collector.NewDefaultCollector(),
		mode:                   constants.RemoteContainer,
		fq:                     fqconfig.NewFilterQueueWithDefaults(),
		mutualAuth:             true,
		validity:               time.Hour * 8760,
		procMountPoint:         constants.DefaultProcMountPoint,
		externalIPcacheTimeout: -1,
	}

	for _, opt := range opts {
		opt(c)
	}

	zap.L().Debug("Trireme configuration", zap.String("configuration", fmt.Sprintf("%+v", c)))

	return newTrireme(c)
}
