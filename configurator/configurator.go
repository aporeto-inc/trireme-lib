// Package configurator provides some helper functions to helpe
// you create default Trireme and Monitor configurations.
package configurator

import (
	"crypto/ecdsa"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/cnimonitor"
	"github.com/aporeto-inc/trireme/monitor/dockermonitor"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"

	"github.com/aporeto-inc/trireme/enforcer/utils/secrets"

	"github.com/aporeto-inc/trireme/enforcer/proxy"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme/supervisor"
	"github.com/aporeto-inc/trireme/supervisor/proxy"
)

const (
	//DefaultProcMountPoint The default proc mountpoint
	DefaultProcMountPoint = "/proc"
	//AporetoProcMountPoint The aporeto proc mountpoint just in case we are launched with some specific docker config
	AporetoProcMountPoint = "/aporetoproc"
)

// NewTriremeLinuxProcess instantiates Trireme for a Linux process implementation
func NewTriremeLinuxProcess(
	serverID string,
	resolver trireme.PolicyResolver,
	processor enforcer.PacketProcessor,
	eventCollector collector.EventCollector,
	secrets secrets.Secrets) trireme.Trireme {

	if eventCollector == nil {
		zap.L().Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	enforcers := map[constants.PUType]enforcer.PolicyEnforcer{
		constants.LinuxProcessPU: enforcer.NewWithDefaults(serverID,
			eventCollector,
			nil,
			secrets,
			constants.LocalServer,
			DefaultProcMountPoint,
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
	processor enforcer.PacketProcessor,
	eventCollector collector.EventCollector,
	secrets secrets.Secrets,
	impl constants.ImplementationType) trireme.Trireme {

	if eventCollector == nil {
		zap.L().Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	enforcers := map[constants.PUType]enforcer.PolicyEnforcer{
		constants.ContainerPU: enforcer.NewWithDefaults(serverID,
			eventCollector,
			nil,
			secrets,
			constants.LocalContainer,
			DefaultProcMountPoint,
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
	processor enforcer.PacketProcessor,
	eventCollector collector.EventCollector,
	secrets secrets.Secrets,
	impl constants.ImplementationType) trireme.Trireme {

	if eventCollector == nil {
		zap.L().Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	rpcwrapper := rpcwrapper.NewRPCWrapper()

	enforcers := map[constants.PUType]enforcer.PolicyEnforcer{
		constants.ContainerPU: enforcerproxy.NewDefaultProxyEnforcer(
			serverID,
			eventCollector,
			secrets,
			rpcwrapper,
			DefaultProcMountPoint,
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
	processor enforcer.PacketProcessor,
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
		DefaultProcMountPoint,
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
		DefaultProcMountPoint,
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

	enforcers := map[constants.PUType]enforcer.PolicyEnforcer{
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

// NewPSKTriremeWithDockerMonitor creates a new network isolator. The calling module must provide
// a policy engine implementation and a pre-shared secret. This is for backward
// compatibility. Will be removed
func NewPSKTriremeWithDockerMonitor(
	serverID string,
	resolver trireme.PolicyResolver,
	processor enforcer.PacketProcessor,
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
	processor enforcer.PacketProcessor,
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
	processor enforcer.PacketProcessor,
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
	processor enforcer.PacketProcessor,
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
	processor enforcer.PacketProcessor,
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
	processor enforcer.PacketProcessor,
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
