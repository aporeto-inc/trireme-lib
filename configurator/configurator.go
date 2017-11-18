// Package configurator provides some helper functions to helpe
// you create default Trireme and Monitor configurations.
package configurator

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib"
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/monitor/cnimonitor"
	"github.com/aporeto-inc/trireme-lib/monitor/dockermonitor"
	"github.com/aporeto-inc/trireme-lib/monitor/linuxmonitor"
	"github.com/aporeto-inc/trireme-lib/monitor/rpcmonitor"

	"github.com/aporeto-inc/trireme-lib/enforcer/policyenforcer"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"

	"github.com/aporeto-inc/trireme-lib/enforcer/proxy"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/rpcwrapper"
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

	CNIMetadataExtractor    rpcmonitor.RPCMetadataExtractor
	DockerMetadataExtractor dockermonitor.DockerMetadataExtractor

	DockerSocketType string
	DockerSocket     string

	Validity                time.Duration
	ExternalIPCacheValidity time.Duration

	FilterQueue *fqconfig.FilterQueue

	ModeType constants.ModeType
	ImplType constants.ImplementationType

	ProcMountPoint        string
	AporetoProcMountPoint string

	RemoteArg string

	RPCAddress              string
	LinuxProcessReleasePath string

	MutualAuth bool

	KillContainerError bool
	SyncAtStart        bool

	PKI bool

	LocalProcess    bool
	LocalContainer  bool
	RemoteContainer bool
	CNI             bool
}

// TriremeResult is the result of the creation of Trireme
type TriremeResult struct {
	Trireme        trireme.Trireme
	DockerMonitor  monitor.Monitor
	RPCMonitor     rpcmonitor.RPCMonitor
	PublicKeyAdder enforcer.PublicKeyAdder
	Secret         secrets.Secrets
}

// DefaultTriremeOptions returns a default set of options.
func DefaultTriremeOptions() *TriremeOptions {
	return &TriremeOptions{
		TargetNetworks: []string{},

		EventCollector: &collector.DefaultCollector{},

		DockerSocketType: constants.DefaultDockerSocketType,
		DockerSocket:     constants.DefaultDockerSocket,

		Validity: time.Hour * 8760,

		FilterQueue:             fqconfig.NewFilterQueueWithDefaults(),
		ExternalIPCacheValidity: -1, // Will get the default from the instantiation.

		ModeType: constants.RemoteContainer,
		ImplType: constants.IPTables,

		ProcMountPoint:        constants.DefaultProcMountPoint,
		AporetoProcMountPoint: constants.DefaultAporetoProcMountPoint,

		RemoteArg: constants.DefaultRemoteArg,

		RPCAddress:              rpcmonitor.DefaultRPCAddress,
		LinuxProcessReleasePath: "",

		MutualAuth: false,

		KillContainerError: false,
		SyncAtStart:        true,

		PKI: false,

		LocalProcess:    true,
		LocalContainer:  false,
		RemoteContainer: true,
		CNI:             false,
	}
}

// NewTriremeWithOptions creates all the Trireme objects based on the option struct
func NewTriremeWithOptions(options *TriremeOptions) (*TriremeResult, error) {

	enforcers := map[constants.PUType]policyenforcer.Enforcer{}
	supervisors := map[constants.PUType]supervisor.Supervisor{}

	var publicKeyAdder enforcer.PublicKeyAdder
	var secretInstance secrets.Secrets
	var dockerMonitorInstance monitor.Monitor
	var rpcMonitorInstance *rpcmonitor.RPCMonitor

	var pkiSecrets secrets.Secrets
	var err error

	// Only a type of Container (remote or local) can be enabled
	if options.RemoteContainer && options.LocalContainer {
		return nil, fmt.Errorf("Cannot have remote and local container enabled at the same time")
	}

	if options.PKI {
		if options.SmartToken != nil {

			zap.L().Info("Initializing Trireme with Smart PKI Auth")
			pkiSecrets, err = secrets.NewCompactPKI(options.KeyPEM, options.CertPEM, options.CaCertPEM, options.SmartToken)
			zap.L().Info("Finished Initializing Trireme with PKI Auth")
			if err != nil {
				return nil, fmt.Errorf("Error Instantiating new Compact PKI: %s", err)
			}
		} else {
			pkiTriremeSecret, err2 := secrets.NewPKISecrets(options.KeyPEM, options.CertPEM, options.CaCertPEM, map[string]*ecdsa.PublicKey{})
			if err2 != nil {
				return nil, fmt.Errorf("Error Instantiating New PKI Secret: %s", err)
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

	triremeInstance := trireme.NewTrireme(options.ServerID, options.Resolver, supervisors, enforcers, options.EventCollector)

	if options.LocalContainer || options.RemoteContainer {
		dockerMonitorInstance = dockermonitor.NewDockerMonitor(
			options.DockerSocketType,
			options.DockerSocket,
			triremeInstance,
			options.DockerMetadataExtractor,
			options.EventCollector,
			options.SyncAtStart,
			nil,
			options.KillContainerError)
	}

	if options.CNI || options.LocalProcess {
		// use rpcmonitor no need to return it since no other consumer for it
		rpcMonitorInstance, err = rpcmonitor.NewRPCMonitor(
			options.RPCAddress,
			options.EventCollector,
			false,
		)
		if err != nil {
			return nil, fmt.Errorf("Failed to initialize RPC monitor %s", err)
		}
	}

	if options.LocalProcess {
		// configure a LinuxServices processor for the rpc monitor
		linuxMonitorProcessor := linuxmonitor.NewLinuxProcessor(
			options.EventCollector,
			triremeInstance,
			linuxmonitor.SystemdRPCMetadataExtractor,
			options.LinuxProcessReleasePath)
		if err := rpcMonitorInstance.RegisterProcessor(
			constants.LinuxProcessPU,
			linuxMonitorProcessor); err != nil {
			zap.L().Fatal("Failed to initialize RPC monitor", zap.Error(err))
		}
	}

	if options.CNI {
		// configure a CNI processor for the rpc monitor
		cniProcessor := cnimonitor.NewCniProcessor(
			options.EventCollector,
			triremeInstance,
			options.CNIMetadataExtractor)
		err := rpcMonitorInstance.RegisterProcessor(
			constants.ContainerPU,
			cniProcessor)
		if err != nil {
			zap.L().Fatal("Failed to initialize RPC monitor", zap.Error(err))
		}
	}

	result := &TriremeResult{
		Trireme:        triremeInstance,
		PublicKeyAdder: publicKeyAdder,
		Secret:         secretInstance,
	}

	if dockerMonitorInstance != nil {
		result.DockerMonitor = dockerMonitorInstance
	}

	if rpcMonitorInstance != nil {
		result.RPCMonitor = *rpcMonitorInstance
	}

	return result, nil
}

// NewPSKTriremeWithDockerMonitor creates a new network isolator. The calling module must provide
// a policy engine implementation and a pre-shared secret. This is for backward
// compatibility. Will be removed
func NewPSKTriremeWithDockerMonitor(
	serverID string,
	resolver trireme.PolicyResolver,
	processor packetprocessor.PacketProcessor,
	eventCollector collector.EventCollector,
	syncAtStart bool,
	key []byte,
	dockerMetadataExtractor dockermonitor.DockerMetadataExtractor,
	remoteEnforcer bool,
	killContainerError bool,
) (trireme.Trireme, monitor.Monitor) {

	if eventCollector == nil {
		zap.L().Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	secrets := NewSecretsFromPSK(key)

	var triremeInstance trireme.Trireme

	if remoteEnforcer {
		triremeInstance = NewDistributedTriremeDocker(
			serverID,
			resolver,
			processor,
			eventCollector,
			secrets,
			constants.IPTables)
	} else {
		triremeInstance = NewLocalTriremeDocker(
			serverID,
			resolver,
			processor,
			eventCollector,
			secrets,
			constants.IPTables)
	}

	monitorInstance := dockermonitor.NewDockerMonitor(
		constants.DefaultDockerSocketType,
		constants.DefaultDockerSocket,
		triremeInstance,
		dockerMetadataExtractor,
		eventCollector,
		syncAtStart,
		nil,
		killContainerError)

	return triremeInstance, monitorInstance

}

// NewPKITriremeWithDockerMonitor creates a new network isolator. The calling module must provide
// a policy engine implementation and private/public key pair and parent certificate.
// All certificates are passed in PEM format. If a certificate pool is provided
// certificates will not be transmitted on the wire
func NewPKITriremeWithDockerMonitor(
	serverID string,
	resolver trireme.PolicyResolver,
	processor packetprocessor.PacketProcessor,
	eventCollector collector.EventCollector,
	syncAtStart bool,
	keyPEM []byte,
	certPEM []byte,
	caCertPEM []byte,
	dockerMetadataExtractor dockermonitor.DockerMetadataExtractor,
	remoteEnforcer bool,
	killContainerError bool,
) (trireme.Trireme, monitor.Monitor, enforcer.PublicKeyAdder) {

	if eventCollector == nil {
		zap.L().Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	publicKeyAdder, err := secrets.NewPKISecrets(keyPEM, certPEM, caCertPEM, map[string]*ecdsa.PublicKey{})
	if err != nil {
		return nil, nil, nil
	}

	var triremeInstance trireme.Trireme

	if remoteEnforcer {
		triremeInstance = NewDistributedTriremeDocker(
			serverID,
			resolver,
			processor,
			eventCollector,
			publicKeyAdder,
			constants.IPTables)
	} else {
		triremeInstance = NewLocalTriremeDocker(
			serverID,
			resolver,
			processor,
			eventCollector,
			publicKeyAdder,
			constants.IPTables)
	}

	monitorInstance := dockermonitor.NewDockerMonitor(
		constants.DefaultDockerSocketType,
		constants.DefaultDockerSocket,
		triremeInstance,
		dockerMetadataExtractor,
		eventCollector,
		syncAtStart,
		nil,
		killContainerError)

	return triremeInstance, monitorInstance, publicKeyAdder

}

// NewPSKHybridTriremeWithMonitor creates a new network isolator. The calling module must provide
// a policy engine implementation and a pre-shared secret. This is for backward
// compatibility. Will be removed
func NewPSKHybridTriremeWithMonitor(
	serverID string,
	networks []string,
	resolver trireme.PolicyResolver,
	processor packetprocessor.PacketProcessor,
	eventCollector collector.EventCollector,
	syncAtStart bool,
	key []byte,
	dockerMetadataExtractor dockermonitor.DockerMetadataExtractor,
	killContainerError bool,
) (trireme.Trireme, monitor.Monitor, monitor.Monitor) {

	if eventCollector == nil {
		zap.L().Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	secrets := NewSecretsFromPSK(key)

	triremeInstance := NewHybridTrireme(
		serverID,
		resolver,
		processor,
		eventCollector,
		secrets,
		networks,
	)

	monitorDocker := dockermonitor.NewDockerMonitor(
		constants.DefaultDockerSocketType,
		constants.DefaultDockerSocket,
		triremeInstance,
		dockerMetadataExtractor,
		eventCollector,
		syncAtStart,
		nil,
		killContainerError,
	)
	// use rpcmonitor no need to return it since no other consumer for it
	rpcmon, err := rpcmonitor.NewRPCMonitor(
		rpcmonitor.DefaultRPCAddress,
		eventCollector,
		false,
	)

	if err != nil {
		zap.L().Fatal("Failed to initialize RPC monitor", zap.Error(err))
	}

	// configure a LinuxServices processor for the rpc monitor
	linuxMonitorProcessor := linuxmonitor.NewLinuxProcessor(eventCollector, triremeInstance, linuxmonitor.SystemdRPCMetadataExtractor, "")
	if err := rpcmon.RegisterProcessor(constants.LinuxProcessPU, linuxMonitorProcessor); err != nil {
		zap.L().Fatal("Failed to initialize RPC monitor", zap.Error(err))
	}

	return triremeInstance, monitorDocker, rpcmon

}

// NewTriremeLinuxProcess instantiates Trireme for a Linux process implementation
func NewTriremeLinuxProcess(
	serverID string,
	resolver trireme.PolicyResolver,
	processor packetprocessor.PacketProcessor,
	eventCollector collector.EventCollector,
	secrets secrets.Secrets) trireme.Trireme {

	if eventCollector == nil {
		zap.L().Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	enforcers := map[constants.PUType]policyenforcer.Enforcer{
		constants.LinuxProcessPU: enforcer.NewWithDefaults(serverID,
			eventCollector,
			nil,
			secrets,
			constants.LocalServer,
			constants.DefaultProcMountPoint,
		)}

	s, err := supervisor.NewSupervisor(
		eventCollector,
		enforcers[constants.LinuxProcessPU],
		constants.LocalServer,
		constants.IPTables,
		[]string{},
	)

	if err != nil {
		zap.L().Fatal("Failed to load Supervisor", zap.Error(err))
	}

	supervisors := map[constants.PUType]supervisor.Supervisor{constants.ContainerPU: s}
	return trireme.NewTrireme(serverID, resolver, supervisors, enforcers, eventCollector)
}

// NewLocalTriremeDocker instantiates Trireme for Docker using enforcement on the
// main namespace
func NewLocalTriremeDocker(
	serverID string,
	resolver trireme.PolicyResolver,
	processor packetprocessor.PacketProcessor,
	eventCollector collector.EventCollector,
	secrets secrets.Secrets,
	impl constants.ImplementationType) trireme.Trireme {

	if eventCollector == nil {
		zap.L().Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	enforcers := map[constants.PUType]policyenforcer.Enforcer{
		constants.ContainerPU: enforcer.NewWithDefaults(serverID,
			eventCollector,
			nil,
			secrets,
			constants.LocalContainer,
			constants.DefaultProcMountPoint,
		)}

	s, err := supervisor.NewSupervisor(
		eventCollector,
		enforcers[constants.ContainerPU],
		constants.LocalContainer,
		impl,
		[]string{},
	)

	if err != nil {
		zap.L().Fatal("Failed to load Supervisor", zap.Error(err))
	}

	supervisors := map[constants.PUType]supervisor.Supervisor{constants.ContainerPU: s}
	return trireme.NewTrireme(serverID, resolver, supervisors, enforcers, eventCollector)
}

// NewDistributedTriremeDocker instantiates Trireme using remote enforcers on
// the container namespaces
func NewDistributedTriremeDocker(serverID string,
	resolver trireme.PolicyResolver,
	processor packetprocessor.PacketProcessor,
	eventCollector collector.EventCollector,
	secrets secrets.Secrets,
	impl constants.ImplementationType) trireme.Trireme {

	if eventCollector == nil {
		zap.L().Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	rpcwrapper := rpcwrapper.NewRPCWrapper()

	enforcers := map[constants.PUType]policyenforcer.Enforcer{
		constants.ContainerPU: enforcerproxy.NewDefaultProxyEnforcer(
			serverID,
			eventCollector,
			secrets,
			rpcwrapper,
			constants.DefaultProcMountPoint,
		),
	}

	s, err := supervisorproxy.NewProxySupervisor(eventCollector, enforcers[0], rpcwrapper)

	if err != nil {
		zap.L().Fatal("Cannot initialize proxy supervisor", zap.Error(err))
	}

	supervisors := map[constants.PUType]supervisor.Supervisor{constants.ContainerPU: s}
	return trireme.NewTrireme(serverID, resolver, supervisors, enforcers, eventCollector)
}

// NewHybridTrireme instantiates Trireme with both Linux and Docker enforcers.
// The Docker enforcers are remote
func NewHybridTrireme(
	serverID string,
	resolver trireme.PolicyResolver,
	processor packetprocessor.PacketProcessor,
	eventCollector collector.EventCollector,
	secrets secrets.Secrets,
	networks []string,
) trireme.Trireme {

	if eventCollector == nil {
		zap.L().Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	rpcwrapper := rpcwrapper.NewRPCWrapper()
	containerEnforcer := enforcerproxy.NewDefaultProxyEnforcer(
		serverID,
		eventCollector,
		secrets,
		rpcwrapper,
		constants.DefaultProcMountPoint,
	)

	containerSupervisor, cerr := supervisorproxy.NewProxySupervisor(
		eventCollector,
		containerEnforcer,
		rpcwrapper)

	if cerr != nil {
		zap.L().Fatal("Failed to load Supervisor", zap.Error(cerr))
	}

	processEnforcer := enforcer.NewWithDefaults(serverID,
		eventCollector,
		processor,
		secrets,
		constants.LocalServer,
		constants.DefaultProcMountPoint,
	)

	processSupervisor, perr := supervisor.NewSupervisor(
		eventCollector,
		processEnforcer,
		constants.LocalServer,
		constants.IPTables,
		networks,
	)

	if perr != nil {
		zap.L().Fatal("Failed to load Supervisor", zap.Error(perr))
	}

	enforcers := map[constants.PUType]policyenforcer.Enforcer{
		constants.ContainerPU:    containerEnforcer,
		constants.LinuxProcessPU: processEnforcer,
	}

	supervisors := map[constants.PUType]supervisor.Supervisor{
		constants.ContainerPU:    containerSupervisor,
		constants.LinuxProcessPU: processSupervisor,
	}

	trireme := trireme.NewTrireme(serverID, resolver, supervisors, enforcers, eventCollector)

	return trireme
}

// NewSecretsFromPSK creates secrets from a pre-shared key
func NewSecretsFromPSK(key []byte) secrets.Secrets {
	return secrets.NewPSKSecrets(key)
}

// NewSecretsFromPKI creates secrets from a PKI
func NewSecretsFromPKI(keyPEM, certPEM, caCertPEM []byte) secrets.Secrets {
	secrets, err := secrets.NewPKISecrets(keyPEM, certPEM, caCertPEM, map[string]*ecdsa.PublicKey{})
	if err != nil {
		return nil
	}
	return secrets
}

// NewHybridCompactPKIWithDocker is an example of configuring Trireme to use the compact PKI
// secrets method. The calling module must provide a policy engine implementation and
// private/public key pair and parent certificate and key.
// All certificates are passed in PEM format. If a certificate pool is provided
// certificates will not be transmitted on the wire.
// This is an example use - certificates must be properly protected
func NewHybridCompactPKIWithDocker(
	serverID string,
	networks []string,
	resolver trireme.PolicyResolver,
	processor packetprocessor.PacketProcessor,
	eventCollector collector.EventCollector,
	syncAtStart bool,
	keyPEM []byte,
	certPEM []byte,
	caCertPEM []byte,
	token []byte,
	dockerMetadataExtractor dockermonitor.DockerMetadataExtractor,
	remoteEnforcer bool,
	killContainerError bool,
) (trireme.Trireme, monitor.Monitor, monitor.Monitor) {

	if eventCollector == nil {
		zap.L().Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	secrets, err := secrets.NewCompactPKI(keyPEM, certPEM, caCertPEM, token)
	if err != nil {
		zap.L().Fatal("Failed to initialize tokens engine")
	}

	triremeInstance := NewHybridTrireme(
		serverID,
		resolver,
		processor,
		eventCollector,
		secrets,
		networks,
	)

	monitorDocker := dockermonitor.NewDockerMonitor(
		constants.DefaultDockerSocketType,
		constants.DefaultDockerSocket,
		triremeInstance,
		dockerMetadataExtractor,
		eventCollector,
		syncAtStart,
		nil,
		killContainerError,
	)

	// use rpcmonitor no need to return it since no other consumer for it
	rpcmon, err := rpcmonitor.NewRPCMonitor(
		rpcmonitor.DefaultRPCAddress,
		eventCollector,
		false,
	)

	if err != nil {
		zap.L().Fatal("Failed to initialize RPC monitor", zap.Error(err))
	}

	// configure a LinuxServices processor for the rpc monitor
	linuxMonitorProcessor := linuxmonitor.NewLinuxProcessor(eventCollector, triremeInstance, linuxmonitor.SystemdRPCMetadataExtractor, "")
	if err := rpcmon.RegisterProcessor(constants.LinuxProcessPU, linuxMonitorProcessor); err != nil {
		zap.L().Fatal("Failed to initialize RPC monitor", zap.Error(err))
	}

	return triremeInstance, monitorDocker, rpcmon

}

// NewCompactPKIWithDocker is an example of configuring Trireme to use the compact PKI
// secrets method. The calling module must provide a policy engine implementation and
// private/public key pair and parent certificate and key.
// All certificates are passed in PEM format. If a certificate pool is provided
// certificates will not be transmitted on the wire.
// This is an example use - certificates must be properly protected
func NewCompactPKIWithDocker(
	serverID string,
	networks []string,
	resolver trireme.PolicyResolver,
	processor packetprocessor.PacketProcessor,
	eventCollector collector.EventCollector,
	syncAtStart bool,
	keyPEM []byte,
	certPEM []byte,
	caCertPEM []byte,
	token []byte,
	dockerMetadataExtractor dockermonitor.DockerMetadataExtractor,
	remoteEnforcer bool,
	killContainerError bool,
) (trireme.Trireme, monitor.Monitor) {

	if eventCollector == nil {
		zap.L().Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	secrets, err := secrets.NewCompactPKI(keyPEM, certPEM, caCertPEM, token)
	if err != nil {
		zap.L().Fatal("Failed to initialize tokens engine")
	}

	triremeInstance := NewDistributedTriremeDocker(
		serverID,
		resolver,
		processor,
		eventCollector,
		secrets,
		constants.IPTables,
	)

	monitorDocker := dockermonitor.NewDockerMonitor(
		constants.DefaultDockerSocketType,
		constants.DefaultDockerSocket,
		triremeInstance,
		dockerMetadataExtractor,
		eventCollector,
		syncAtStart,
		nil,
		killContainerError,
	)

	return triremeInstance, monitorDocker

}

// NewPSKTriremeWithCNIMonitor simple CNI monitor
func NewPSKTriremeWithCNIMonitor(
	serverID string,
	resolver trireme.PolicyResolver,
	processor packetprocessor.PacketProcessor,
	eventCollector collector.EventCollector,
	key []byte,
	cniMetadataExtractor rpcmonitor.RPCMetadataExtractor,
	remoteEnforcer bool,
) (trireme.Trireme, monitor.Monitor) {

	if eventCollector == nil {
		zap.L().Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	secrets := NewSecretsFromPSK(key)

	var triremeInstance trireme.Trireme

	if remoteEnforcer {
		triremeInstance = NewDistributedTriremeDocker(
			serverID,
			resolver,
			processor,
			eventCollector,
			secrets,
			constants.IPTables)
	} else {
		triremeInstance = NewLocalTriremeDocker(
			serverID,
			resolver,
			processor,
			eventCollector,
			secrets,
			constants.IPTables)
	}

	rpcmon, err := rpcmonitor.NewRPCMonitor(
		rpcmonitor.DefaultRPCAddress,
		eventCollector,
		false,
	)
	if err != nil {
		zap.L().Fatal("Failed to initialize RPC monitor", zap.Error(err))
	}

	// configure a LinuxServices processor for the rpc monitor
	cniProcessor := cnimonitor.NewCniProcessor(eventCollector, triremeInstance, cniMetadataExtractor)
	if err := rpcmon.RegisterProcessor(constants.ContainerPU, cniProcessor); err != nil {
		zap.L().Fatal("Failed to initialize RPC monitor", zap.Error(err))
	}

	return triremeInstance, rpcmon

}
