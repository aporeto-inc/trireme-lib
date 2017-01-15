// Package configurator provides some helper functions to helpe
// you create default Trireme and Monitor configurations.
package configurator

import (
	"crypto/ecdsa"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/monitor/dockermonitor"

	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"

	"github.com/aporeto-inc/trireme/enforcer/proxy"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/supervisor"
	"github.com/aporeto-inc/trireme/supervisor/proxy"
)

// NewTriremeWithDockerMonitor TODO
func NewTriremeWithDockerMonitor(
	serverID string,
	networks []string,
	resolver trireme.PolicyResolver,
	processor enforcer.PacketProcessor,
	eventCollector collector.EventCollector,
	secrets tokens.Secrets,
	syncAtStart bool,
	dockerMetadataExtractor dockermonitor.DockerMetadataExtractor,
	RemoteEnforcer bool,
) (trireme.Trireme, monitor.Monitor, supervisor.Excluder) {
	enforcers := make([]enforcer.PolicyEnforcer, 2)
	supervisors := make([]supervisor.Supervisor, 2)
	if eventCollector == nil {
		log.WithFields(log.Fields{
			"package": "configurator",
		}).Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}
	rpcwrapper := rpcwrapper.NewRPCWrapper()
	enforcers[trireme.RemoteEnforcer] = enforcerproxy.NewDefaultProxyEnforcer(serverID, eventCollector, secrets, rpcwrapper)
	s, err := supervisorproxy.NewProxySupervisor(eventCollector, enforcers[trireme.RemoteEnforcer], networks, rpcwrapper)
	supervisors[trireme.RemoteEnforcer] = s

	enforcers[trireme.LocalEnforcer] = enforcer.NewDefaultDatapathEnforcer(serverID,
		eventCollector,
		nil,
		secrets,
		constants.LocalServer,
	)

	supervisors[trireme.LocalEnforcer], err = supervisor.NewSupervisor(
		eventCollector,
		enforcers[trireme.LocalEnforcer],
		networks,
		constants.LocalServer,
		constants.IPTables,
	)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "configurator",
			"error":   err.Error(),
		}).Fatal("Failed to load Supervisor")

	}
	trireme := trireme.NewTrireme(serverID, resolver, supervisors, enforcers, eventCollector)
	dockermonitor := dockermonitor.NewDockerMonitor(constants.DefaultDockerSocketType, constants.DefaultDockerSocket, trireme, dockerMetadataExtractor, eventCollector, syncAtStart, nil)
	return trireme, dockermonitor, supervisors[0].(supervisor.Excluder)

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
	dockerMetadataExtractor dockermonitor.DockerMetadataExtractor,
	RemoteEnforcer bool,
) (trireme.Trireme, monitor.Monitor, supervisor.Excluder) {
	return NewTriremeWithDockerMonitor(serverID, networks, resolver, processor, eventCollector, tokens.NewPSKSecrets(key), syncAtStart, dockerMetadataExtractor, RemoteEnforcer)

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
	dockerMetadataExtractor dockermonitor.DockerMetadataExtractor,
	RemoteEnforcer bool,
) (trireme.Trireme, monitor.Monitor, supervisor.Excluder, enforcer.PublicKeyAdder) {

	publicKeyAdder := tokens.NewPKISecrets(keyPEM, certPEM, caCertPEM, map[string]*ecdsa.PublicKey{})

	trireme, monitor, excluder := NewTriremeWithDockerMonitor(serverID, networks, resolver, processor, eventCollector, publicKeyAdder, syncAtStart, dockerMetadataExtractor, RemoteEnforcer)

	return trireme, monitor, excluder, publicKeyAdder
}
