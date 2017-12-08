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
	"github.com/aporeto-inc/trireme-lib/enforcer/packetprocessor"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/processor"
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

// DefaultTriremeOptions returns a default set of options.
func DefaultTriremeOptions() *TriremeOptions {

	localProcess := true
	localContainer := false
	remoteContainer := true
	eventCollector := &collector.DefaultCollector{}

	return &TriremeOptions{
		TargetNetworks: []string{},

		EventCollector: eventCollector,

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

		LocalProcess:    localProcess,
		LocalContainer:  localContainer,
		RemoteContainer: remoteContainer,

		// Monitor
		Monitor: monitor.SetupConfig(
			// LinuxProcess
			localProcess,
			nil,
			// LinuxHost
			false,
			nil,
			// UID
			false,
			nil,
			// Docker
			localContainer || remoteContainer,
			nil,
			// CNI
			false,
			nil,
			&processor.Config{
				Collector: eventCollector,
				MergeTags: []string{},
			},
		),
	}
}

// NewTriremeWithOptions creates all the Trireme objects based on the option struct
func NewTriremeWithOptions(options *TriremeOptions) (*TriremeResult, error) {

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

	var tmode constants.ModeType = constants.LocalContainer
	if options.RemoteContainer {
		tmode = constants.RemoteContainer
	}
	triremeInstance := trireme.NewTrireme(
		options.ServerID,
		options.Resolver,
		tmode,
		options.LocalProcess,
		options.EventCollector,
		nil,
		true,
		secretInstance,
		options.FilterQueue,
		options.Validity,
		options.ProcMountPoint,
		options.TargetNetworks,
		options.ExternalIPCacheValidity,
		[]string{})

	options.Monitor.Common.PUHandler = triremeInstance

	monitors, err := monitor.New(options.Monitor)
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
