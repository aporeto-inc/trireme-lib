// Package configurator provides some helper functions to helpe
// you create default Trireme and Monitor configurations.
package configurator

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/tokens"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/supervisor"
)

const (
	// DefaultDockerSocket is the default socket to use to communicate with docker
	DefaultDockerSocket = "/var/run/docker.sock"

	// DefaultDockerSocketType is unix
	DefaultDockerSocketType = "unix"
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
) (trireme.Trireme, monitor.Monitor) {

	if eventCollector == nil {
		eventCollector = &collector.DefaultCollector{}
	}

	// Make sure that the iptables command is accessible. Panic if its not there.
	ipt, err := supervisor.NewGoIPTablesProvider()
	if err != nil {
		fmt.Printf("Failed to load Go-Iptables: %s", err)
		panic("Failed to load Go-Iptables: ")
	}

	enforcer := enforcer.NewDefaultDatapathEnforcer(serverID, eventCollector, secrets)
	supervisor, _ := supervisor.NewIPTablesSupervisor(eventCollector, enforcer, ipt, networks)
	trireme := trireme.NewTrireme(serverID, resolver, supervisor, enforcer)
	monitor := monitor.NewDockerMonitor(DefaultDockerSocketType, DefaultDockerSocket, trireme, nil, eventCollector, syncAtStart)

	return trireme, monitor
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
) (trireme.Trireme, monitor.Monitor) {

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
) (trireme.Trireme, monitor.Monitor, enforcer.PublicKeyAdder) {

	publicKeyAdder := tokens.NewPKISecrets(keyPEM, certPEM, caCertPEM, map[string]*ecdsa.PublicKey{})

	trireme, monitor := NewTriremeWithDockerMonitor(serverID, networks, resolver, processor, eventCollector, publicKeyAdder, syncAtStart)

	return trireme, monitor, publicKeyAdder
}
