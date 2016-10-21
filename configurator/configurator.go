// Package configurator provides some helper functions to helpe
// you create default Trireme and Monitor configurations.
package configurator

import (
	"crypto/ecdsa"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/controller"
	"github.com/aporeto-inc/trireme/datapath"
	"github.com/aporeto-inc/trireme/datapath/tokens"
	"github.com/aporeto-inc/trireme/eventlog"
	"github.com/aporeto-inc/trireme/monitor"
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
	targetNetworks []string,
	policyEngine trireme.PolicyResolver,
	svcImpl datapath.Service,
	secrets tokens.Secrets,
	syncAtStart bool,
) (trireme.Trireme, monitor.Monitor) {

	dp := datapath.NewDefault(serverID, secrets)
	eventLogger := &eventlog.DefaultLogger{}
	controller := controller.New(eventLogger, dp, targetNetworks)

	trireme := trireme.NewTrireme(serverID, dp, controller, policyEngine)
	monitor := monitor.NewDockerMonitor(DefaultDockerSocketType, DefaultDockerSocket, trireme, nil, eventLogger, syncAtStart)

	return trireme, monitor
}

// NewPSKTriremeWithDockerMonitor creates a new network isolator. The calling module must provide
// a policy engine implementation and a pre-shared secret
func NewPSKTriremeWithDockerMonitor(
	serverID string,
	targetNetworks []string,
	policyEngine trireme.PolicyResolver,
	svcImpl datapath.Service,
	syncAtStart bool,
	key []byte,
) (trireme.Trireme, monitor.Monitor) {

	return NewTriremeWithDockerMonitor(serverID, targetNetworks, policyEngine, svcImpl, tokens.NewPSKSecrets(key), syncAtStart)
}

// NewPKITriremeWithDockerMonitor creates a new network isolator. The calling module must provide
// a policy engine implementation and private/public key pair and parent certificate.
// All certificates are passed in PEM format. If a certificate pool is provided
// certificates will not be transmitted on the wire
func NewPKITriremeWithDockerMonitor(
	serverID string,
	targetNetworks []string,
	policyEngine trireme.PolicyResolver,
	svcImpl datapath.Service,
	syncAtStart bool,
	keyPEM []byte,
	certPEM []byte,
	caCertPEM []byte,
) (trireme.Trireme, monitor.Monitor, datapath.PublicKeyAdder) {

	publicKeyAdder := tokens.NewPKISecrets(keyPEM, certPEM, caCertPEM, map[string]*ecdsa.PublicKey{})

	trireme, monitor := NewTriremeWithDockerMonitor(serverID, targetNetworks, policyEngine, svcImpl, publicKeyAdder, syncAtStart)

	return trireme, monitor, publicKeyAdder
}
