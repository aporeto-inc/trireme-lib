// Package configurator provides some helper functions to helpe
// you create default Trireme and Monitor configurations.
package configurator

import (
	"crypto/ecdsa"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"

	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"

	"github.com/aporeto-inc/trireme/enforcer/proxy"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/supervisor"
	"github.com/aporeto-inc/trireme/supervisor/proxy"
)

const (
	// DefaultDockerSocket is the default socket to use to communicate with docker
	DefaultDockerSocket = "/var/run/docker.sock"

	// DefaultDockerSocketType is unix
	DefaultDockerSocketType = "unix"
)

// NewIPSetSupervisor is the Supervisor based on IPSets.
func NewIPSetSupervisor(eventCollector collector.EventCollector, enforcer enforcer.PolicyEnforcer, networks []string) (supervisor.Supervisor, error) {

	return supervisor.NewSupervisor(eventCollector, enforcer, networks, supervisor.LocalContainer, supervisor.IPSets)

}

// NewIPTablesSupervisor is the current old supervisor implementation.
func NewIPTablesSupervisor(eventCollector collector.EventCollector, enforcer enforcer.PolicyEnforcer, networks []string) (supervisor.Supervisor, error) {

	return supervisor.NewSupervisor(eventCollector, enforcer, networks, supervisor.LocalContainer, supervisor.IPTables)

}

// NewDefaultSupervisor returns the IPTables supervisor
func NewDefaultSupervisor(eventCollector collector.EventCollector, enforcer enforcer.PolicyEnforcer, networks []string) (supervisor.Supervisor, error) {
	return NewIPTablesSupervisor(eventCollector, enforcer, networks)
}

// NewTriremeWithDockerMonitor TODO
func NewTriremeWithDockerMonitor(
	serverID string,
	networks []string,
	resolver trireme.PolicyResolver,
	processor enforcer.PacketProcessor,
	eventCollector collector.EventCollector,
	secrets tokens.Secrets,
	syncAtStart bool,
	dockerMetadataExtractor monitor.DockerMetadataExtractor,
	remoteEnforcer bool,
) (trireme.Trireme, monitor.Monitor, supervisor.Excluder) {

	if eventCollector == nil {
		log.WithFields(log.Fields{
			"package": "configurator",
		}).Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	if remoteEnforcer {
		//processmonitor := ProcessMon.NewProcessMon()
		rpcwrapper := rpcwrapper.NewRPCWrapper()

		proxyEnforce := enforcerproxy.NewDefaultProxyEnforcer(serverID, eventCollector, secrets, rpcwrapper)
		proxySupervise, err := supervisorproxy.NewProxySupervisor(eventCollector, proxyEnforce, networks, rpcwrapper)
		if err != nil {
			log.WithFields(log.Fields{
				"package": "configurator",
				"error":   err.Error(),
			}).Fatal("Failed to load Supervisor")

		}
		trireme := trireme.NewTrireme(serverID, resolver, proxySupervise, proxyEnforce)
		monitor := monitor.NewDockerMonitor(DefaultDockerSocketType, DefaultDockerSocket, trireme, dockerMetadataExtractor, eventCollector, syncAtStart, nil)
		return trireme, monitor, proxySupervise.(supervisor.Excluder)
	}

	localEnforcer := enforcer.NewDefaultDatapathEnforcer(serverID, eventCollector, nil, secrets, remoteEnforcer)
	localSupervisor, err := NewDefaultSupervisor(eventCollector, localEnforcer, networks)

	// TODO: Supervisor can be automatically iptables or ipsets. If you want to start
	// an ipsets based supervisor replace the line above with the below
	// localSupervisor, err := NewIPSetSupervisor(eventCollector, localEnforcer, networks)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "configurator",
			"error":   err.Error(),
		}).Fatal("Failed to load Supervisor")

	}
	trireme := trireme.NewTrireme(serverID, resolver, localSupervisor, localEnforcer)

	monitor := monitor.NewDockerMonitor(DefaultDockerSocketType, DefaultDockerSocket, trireme, dockerMetadataExtractor, eventCollector, syncAtStart, nil)

	return trireme, monitor, localSupervisor.(supervisor.Excluder)

}

// NewPSKTriremeWithDockerMonitor creates a new network isolator. The calling module must provide
// a policy engine implementation and a pre-shared secret
func NewPSKTriremeWithDockerMonitor(
	serverID string,
	networks []string,
	resolver trireme.PolicyResolver,
	processor enforcer.PacketProcessor,
	eventCollector collector.EventCollector,
	syncAtStart bool,
	key []byte,
	dockerMetadataExtractor monitor.DockerMetadataExtractor,
	remoteEnforcer bool,
) (trireme.Trireme, monitor.Monitor, supervisor.Excluder) {
	return NewTriremeWithDockerMonitor(serverID, networks, resolver, processor, eventCollector, tokens.NewPSKSecrets(key), syncAtStart, dockerMetadataExtractor, remoteEnforcer)

}

// NewPKITriremeWithDockerMonitor creates a new network isolator. The calling module must provide
// a policy engine implementation and private/public key pair and parent certificate.
// All certificates are passed in PEM format. If a certificate pool is provided
// certificates will not be transmitted on the wire
func NewPKITriremeWithDockerMonitor(
	serverID string,
	networks []string,
	resolver trireme.PolicyResolver,
	processor enforcer.PacketProcessor,
	eventCollector collector.EventCollector,
	syncAtStart bool,
	keyPEM []byte,
	certPEM []byte,
	caCertPEM []byte,
	dockerMetadataExtractor monitor.DockerMetadataExtractor,
	remoteEnforcer bool,
) (trireme.Trireme, monitor.Monitor, supervisor.Excluder, enforcer.PublicKeyAdder) {

	publicKeyAdder := tokens.NewPKISecrets(keyPEM, certPEM, caCertPEM, map[string]*ecdsa.PublicKey{})

	trireme, monitor, excluder := NewTriremeWithDockerMonitor(serverID, networks, resolver, processor, eventCollector, publicKeyAdder, syncAtStart, dockerMetadataExtractor, remoteEnforcer)

	return trireme, monitor, excluder, publicKeyAdder
}
