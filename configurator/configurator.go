// Package configurator provides some helper functions to helpe
// you create default Trireme and Monitor configurations.
package configurator

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib"
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer"
	"github.com/aporeto-inc/trireme-lib/enforcer/packetprocessor"
	"github.com/aporeto-inc/trireme-lib/enforcer/policyenforcer"
	"github.com/aporeto-inc/trireme-lib/enforcer/proxy"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/supervisor"
	"github.com/aporeto-inc/trireme-lib/supervisor/proxy"
)

// TriremeOptions defines all the possible configuration options for Trireme configurator
type TriremeOptions struct {
	ServerID string

	PSK []byte

	KeyPEM     []byte
	CertPEM    []byte
	CaCertPEM  []byte
	SmartToken []byte

	TargetNetworks []string

	Resolver       trireme.PolicyResolver
	EventCollector collector.EventCollector
	Processor      packetprocessor.PacketProcessor

	Validity                time.Duration
	ExternalIPCacheValidity time.Duration

	FilterQueue *fqconfig.FilterQueue

	ModeType constants.ModeType
	ImplType constants.ImplementationType

	ProcMountPoint        string
	AporetoProcMountPoint string

	RemoteArg string

	MutualAuth bool

	PKI bool

	LocalProcess    bool
	LocalContainer  bool
	RemoteContainer bool

	// Monitor Configuration
	Monitor *monitor.Config
}

// TriremeResult is the result of the creation of Trireme
type TriremeResult struct {
	Trireme        trireme.Trireme
	PublicKeyAdder secrets.PublicKeyAdder
	Secret         secrets.Secrets
	Monitors       monitor.Monitor
}

// OptMonitorConfig provides a way to specify monitor specific configuration.
func OptMonitorConfig(cfg *monitor.Config) func(t *TriremeOptions) {
	return func(t *TriremeOptions) {
		t.Monitor = cfg
	}
}

// DefaultTriremeOptions returns a default set of options.
func DefaultTriremeOptions(trireme trireme.Trireme, opts ...func(*TriremeOptions)) *TriremeOptions {

	// Initialize with required arguments
	t := &TriremeOptions{
		TargetNetworks: []string{},
		EventCollector: &collector.DefaultCollector{},

		Validity: time.Hour * 8760,

		FilterQueue:             fqconfig.NewFilterQueueWithDefaults(),
		ExternalIPCacheValidity: -1, // Will get the default from the instantiation.

		ModeType: constants.RemoteContainer,
		ImplType: constants.IPTables,

		ProcMountPoint:        constants.DefaultProcMountPoint,
		AporetoProcMountPoint: constants.DefaultAporetoProcMountPoint,

		RemoteArg: constants.DefaultRemoteArg,

		MutualAuth: false,

		PKI: false,

		LocalProcess:    true,
		LocalContainer:  false,
		RemoteContainer: true,
	}

	// Collect all options provided.
	for _, opt := range opts {
		opt(t)
	}

	// Setup missing optional stuff
	if t.Monitor == nil {
		// Setup default monitors
		OptMonitorConfig(
			monitor.SetupConfig(
				monitor.OptMonitorLinux(false),
				monitor.OptMonitorDocker(),
				monitor.OptProcessorConfig(t.EventCollector, trireme, nil),
			),
		)(t)
	}

	return t
}

// NewTriremeWithOptions creates all the Trireme objects based on the option struct
func NewTriremeWithOptions(options *TriremeOptions) (*TriremeResult, error) {

	enforcers := map[constants.PUType]policyenforcer.Enforcer{}
	supervisors := map[constants.PUType]supervisor.Supervisor{}

	var publicKeyAdder secrets.PublicKeyAdder
	var secretInstance secrets.Secrets

	var pkiSecrets secrets.Secrets
	var err error

	// Only a type of Container (remote or local) can be enabled
	if options.RemoteContainer && options.LocalContainer {
		return nil, errors.New("cannot have remote and local container enabled at the same time")
	}

	if options.PKI {
		if options.SmartToken != nil {

			zap.L().Debug("Initializing Trireme with Smart PKI Auth")
			pkiSecrets, err = secrets.NewCompactPKI(options.KeyPEM, options.CertPEM, options.CaCertPEM, options.SmartToken)
			if err != nil {
				return nil, fmt.Errorf("unable to instantiate new compact pki: %s", err)
			}
		} else {
			pkiTriremeSecret, err2 := secrets.NewPKISecrets(options.KeyPEM, options.CertPEM, options.CaCertPEM, map[string]*ecdsa.PublicKey{})
			if err2 != nil {
				return nil, fmt.Errorf("unable to instantiate new pki secret: %s", err)
			}
			pkiSecrets = pkiTriremeSecret
			publicKeyAdder = pkiTriremeSecret
		}
		secretInstance = pkiSecrets

	} else {
		secretInstance = NewSecretsFromPSK(options.PSK)
	}

	if options.RemoteContainer {
		var s supervisor.Supervisor

		rpcwrapper := rpcwrapper.NewRPCWrapper()
		e := enforcerproxy.NewProxyEnforcer(
			options.MutualAuth,
			options.FilterQueue,
			options.EventCollector,
			options.Processor,
			secretInstance,
			options.ServerID,
			options.Validity,
			rpcwrapper,
			options.RemoteArg,
			options.ProcMountPoint,
			options.ExternalIPCacheValidity,
		)

		s, err = supervisorproxy.NewProxySupervisor(
			options.EventCollector,
			e,
			rpcwrapper)

		if err != nil {
			zap.L().Fatal("Failed to load Supervisor", zap.Error(err))
		}
		enforcers[constants.ContainerPU] = e
		supervisors[constants.ContainerPU] = s
	}

	if options.LocalContainer {
		var s supervisor.Supervisor

		e := enforcer.New(
			options.MutualAuth,
			options.FilterQueue,
			options.EventCollector,
			options.Processor,
			secretInstance,
			options.ServerID,
			options.Validity,
			constants.LocalContainer,
			options.ProcMountPoint,
			options.ExternalIPCacheValidity,
		)

		s, err = supervisor.NewSupervisor(
			options.EventCollector,
			e,
			constants.LocalContainer,
			options.ImplType,
			options.TargetNetworks,
		)
		if err != nil {
			zap.L().Fatal("Failed to load Supervisor", zap.Error(err))
		}

		enforcers[constants.ContainerPU] = e
		supervisors[constants.ContainerPU] = s
	}

	if options.LocalProcess {
		var s supervisor.Supervisor

		e := enforcer.New(
			options.MutualAuth,
			options.FilterQueue,
			options.EventCollector,
			options.Processor,
			secretInstance,
			options.ServerID,
			options.Validity,
			constants.LocalServer,
			options.ProcMountPoint,
			options.ExternalIPCacheValidity,
		)

		s, err = supervisor.NewSupervisor(
			options.EventCollector,
			e,
			constants.LocalServer,
			options.ImplType,
			options.TargetNetworks,
		)
		if err != nil {
			zap.L().Fatal("Failed to load Supervisor", zap.Error(err))
		}

		enforcers[constants.LinuxProcessPU] = e
		supervisors[constants.LinuxProcessPU] = s

	}

	triremeInstance := trireme.NewTrireme(options.ServerID, options.Resolver, supervisors, enforcers, options.EventCollector, []string{})

	monitors, err := monitor.NewMonitors(options.Monitor)
	if err != nil {
		zap.L().Fatal("Failed to load Supervisor", zap.Error(err))
	}

	result := &TriremeResult{
		Trireme:        triremeInstance,
		PublicKeyAdder: publicKeyAdder,
		Secret:         secretInstance,
		Monitors:       monitors,
	}

	return result, nil
}

// NewSecretsFromPSK creates secrets from a pre-shared key
func NewSecretsFromPSK(key []byte) secrets.Secrets {
	return secrets.NewPSKSecrets(key)
}
