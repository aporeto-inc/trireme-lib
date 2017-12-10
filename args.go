package trireme

import (
	"fmt"
	"time"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/packetprocessor"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/monitor"
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
	validity               time.Duration
	procMountPoint         string
	externalIPcacheTimeout time.Duration
	targetNetworks         []string
}

// Option is provided using functional arguments.
type Option func(*config)

// OptionCollector is an option to provide an external collector implementation.
func OptionCollector(c collector.EventCollector) func(*config) {
	return func(cfg *config) {
		cfg.collector = c
	}
}

// OptionPolicyResolver is an option to provide an external policy resolver implementation.
func OptionPolicyResolver(r PolicyResolver) func(*config) {
	return func(cfg *config) {
		cfg.resolver = r
	}
}

// OptionDatapathService is an option to provide an external datapath service implementation.
func OptionDatapathService(s packetprocessor.PacketProcessor) func(*config) {
	return func(cfg *config) {
		cfg.service = s
	}
}

// OptionSecret is an option to provide an external datapath service implementation.
func OptionSecret(s secrets.Secrets) func(*config) {
	return func(cfg *config) {
		cfg.secret = s
	}
}

// OptionMonitors is an option to provide configurations for monitors.
func OptionMonitors(m *monitor.Config) func(*config) {
	return func(cfg *config) {
		cfg.monitors = m
	}
}

// OptionEnforceLocal is an option to request local enforcer. Absence of this options
// implies use remote enforcers.
func OptionEnforceLocal() func(*config) {
	return func(cfg *config) {
		cfg.mode = constants.LocalContainer
	}
}

// OptionEnforceLinuxProcess is an option to request support for linux process support.
func OptionEnforceLinuxProcess() func(*config) {
	return func(cfg *config) {
		cfg.linuxProcess = true
	}
}

// OptionEnforceFqConfig is an option to override filter queues.
func OptionEnforceFqConfig(f *fqconfig.FilterQueue) func(*config) {
	return func(cfg *config) {
		cfg.fq = f
	}
}

// OptionTargetNetworks is an option to provide target network configuration.
func OptionTargetNetworks(n []string) func(*config) {
	return func(cfg *config) {
		cfg.targetNetworks = n
	}
}

// OptionProcMountPoint is an option to provide proc mount point.
func OptionProcMountPoint(p string) func(*config) {
	return func(cfg *config) {
		cfg.procMountPoint = p
	}
}

// New returns a trireme interface implementation based on configuration provided.
func New(serverID string, opts ...Option) Trireme {

	c := &config{
		serverID:               serverID,
		mode:                   constants.RemoteContainer,
		mutualAuth:             true,
		validity:               time.Hour * 8760,
		procMountPoint:         constants.DefaultProcMountPoint,
		externalIPcacheTimeout: -1,
	}

	for _, opt := range opts {
		opt(c)
	}

	zap.L().Info("Trireme", zap.String("Configuration", fmt.Sprintf("%+v", c)))

	return NewTrireme(c)
}
