package trireme

import (
	"crypto/ecdsa"

	"github.com/aporeto-inc/trireme/controller"
	"github.com/aporeto-inc/trireme/datapath"
	"github.com/aporeto-inc/trireme/datapath/tokens"
	"github.com/aporeto-inc/trireme/eventlog"
	"github.com/aporeto-inc/trireme/interfaces"
	"github.com/aporeto-inc/trireme/monitor"
)

const (
	// DefaultDockerSocket is the default socket to use to communicate with docker
	DefaultDockerSocket = "/var/run/docker.sock"
	// DefaultDockerSocketType is unix
	DefaultDockerSocketType = "unix"
)

// Helper holds the configuration of an isolator
type Helper struct {
	EventLogger eventlog.EventLogger
	SvcImpl     datapath.Service
	ServerID    string
	SyncAtStart bool

	PkAdder        interfaces.PublicKeyAdder
	targetNetworks []string
	secrets        tokens.Secrets
	dp             *datapath.DataPath
	controller     *controller.Controller
	Monitor        *monitor.Docker
	policyEngine   interfaces.PolicyResolver
	Trireme        interfaces.Trireme
}

// NewTrireme TODO
func NewTrireme(serverID string, targetNetworks []string, policyEngine interfaces.PolicyResolver, svcImpl datapath.Service, secrets tokens.Secrets, syncAtStart bool) *Helper {

	helper := Helper{
		EventLogger: &eventlog.DefaultLogger{},
		SvcImpl:     svcImpl,
		ServerID:    serverID,
		SyncAtStart: syncAtStart,

		secrets:        secrets,
		policyEngine:   policyEngine,
		targetNetworks: targetNetworks,
	}

	dp := datapath.NewDefault(
		helper.ServerID,
		helper.secrets,
	)
	if dp == nil {
		panic("Error creating Datapath")
	}
	helper.dp = dp

	// Instantiate the controller
	controller := controller.New(
		helper.EventLogger,
		helper.dp,
		helper.targetNetworks,
	)
	if controller == nil {
		panic("Failed to create controller")
	}
	helper.controller = controller

	trireme := New(serverID, helper.dp, helper.controller, helper.policyEngine)
	helper.Trireme = trireme

	monitor, err := monitor.NewDockerMonitor(
		DefaultDockerSocketType,
		DefaultDockerSocket,
		trireme,
		nil,
		helper.EventLogger,
		helper.SyncAtStart)
	if err != nil {
		panic("Error creating new Docker Monitor")
	}
	helper.Monitor = monitor

	return &helper
}

// NewPKITrireme creates a new network isolator. The calling module must provide
// a policy engine implementation and private/public key pair and parent certificate.
// All certificates are passed in PEM format. If a certificate pool is provided
// certificates will not be transmitted on the wire
func NewPKITrireme(serverID string, targetNetworks []string, policyEngine interfaces.PolicyResolver, svcImpl datapath.Service, syncAtStart bool, keyPEM, certPEM, caCertPEM []byte) *Helper {
	certCache := map[string]*ecdsa.PublicKey{}
	tokens := tokens.NewPKISecrets(keyPEM, certPEM, caCertPEM, certCache)
	helper := NewTrireme(
		serverID,
		targetNetworks,
		policyEngine,
		svcImpl,
		tokens,
		syncAtStart,
	)
	helper.PkAdder = tokens
	return helper
}

// NewPSKTrireme creates a new network isolator. The calling module must provide
// a policy engine implementation and a pre-shared secret
func NewPSKTrireme(serverID string, targetNetworks []string, policyEngine interfaces.PolicyResolver, svcImpl datapath.Service, syncAtStart bool, key []byte) *Helper {

	return NewTrireme(
		serverID,
		targetNetworks,
		policyEngine,
		svcImpl,
		tokens.NewPSKSecrets(key),
		syncAtStart,
	)
}
