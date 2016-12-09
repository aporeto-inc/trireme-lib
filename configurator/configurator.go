// Package configurator provides some helper functions to helpe
// you create default Trireme and Monitor configurations.
package configurator

import (
	"crypto/ecdsa"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/tokens"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/supervisor"
	"github.com/aporeto-inc/trireme/supervisor/iptablesutils"
	"github.com/aporeto-inc/trireme/supervisor/provider"
)

const (
	// DefaultDockerSocket is the default socket to use to communicate with docker
	DefaultDockerSocket = "/var/run/docker.sock"

	// DefaultDockerSocketType is unix
	DefaultDockerSocketType = "unix"
)

// NewIPSetSupervisor is the Supervisor based on IPSets.
func NewIPSetSupervisor(eventCollector collector.EventCollector, enforcer enforcer.PolicyEnforcer, networks []string) (supervisor.Supervisor, error) {
	// Make sure that the iptables command is accessible. Panic if its not there.
	ipt, err := provider.NewGoIPTablesProvider()
	if err != nil {
		return nil, err
	}

	ipu := iptablesutils.NewIpsetUtils()

	ips := provider.NewGoIPsetProvider()

	return supervisor.NewIPSetSupervisor(eventCollector, enforcer, ipt, ips, ipu, networks)
}

// NewIPTablesSupervisor is the current old supervisor implementation.
func NewIPTablesSupervisor(eventCollector collector.EventCollector, enforcer enforcer.PolicyEnforcer, networks []string) (supervisor.Supervisor, error) {

	ipu := iptablesutils.NewIptableUtils()

	// Make sure that the iptables command is accessible. Panic if its not there.
	ipt, err := provider.NewGoIPTablesProvider()
	if err != nil {
		return nil, err
	}

	return supervisor.NewIPTablesSupervisor(eventCollector, enforcer, ipt, ipu, networks)
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
) (trireme.Trireme, monitor.Monitor, supervisor.Excluder) {

	if eventCollector == nil {
		log.WithFields(log.Fields{
			"package": "configurator",
		}).Warn("Using a default collector for events")
		eventCollector = &collector.DefaultCollector{}
	}

	enforcer := enforcer.NewDefaultDatapathEnforcer(serverID, eventCollector, processor, secrets)
	IPTsupervisor, err := NewDefaultSupervisor(eventCollector, enforcer, networks)
	// Make sure that the Supervisor was able to load. Panic if its not there.
	if err != nil {
		log.WithFields(log.Fields{
			"package": "configurator",
			"error":   err.Error(),
		}).Fatal("Failed to load Supervisor")
	}

	trireme := trireme.NewTrireme(serverID, resolver, IPTsupervisor, enforcer)
	monitor := monitor.NewDockerMonitor(DefaultDockerSocketType, DefaultDockerSocket, trireme, nil, eventCollector, syncAtStart)

	return trireme, monitor, IPTsupervisor.(supervisor.Excluder)
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
) (trireme.Trireme, monitor.Monitor, supervisor.Excluder) {

	return NewTriremeWithDockerMonitor(serverID, networks, resolver, processor, eventCollector, tokens.NewPSKSecrets(key), syncAtStart)
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
) (trireme.Trireme, monitor.Monitor, supervisor.Excluder, enforcer.PublicKeyAdder) {

	publicKeyAdder := tokens.NewPKISecrets(keyPEM, certPEM, caCertPEM, map[string]*ecdsa.PublicKey{})

	trireme, monitor, excluder := NewTriremeWithDockerMonitor(serverID, networks, resolver, processor, eventCollector, publicKeyAdder, syncAtStart)

	return trireme, monitor, excluder, publicKeyAdder
}
