package common

import (
	"encoding/pem"
	"io/ioutil"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/configurator"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/dockermonitor"
)

var (
	// ExternalProcessor to use if needed
	ExternalProcessor enforcer.PacketProcessor
)

// TriremeWithPKI is a helper method to created a PKI implementation of Trireme
func TriremeWithPKI(keyFile, certFile, caCertFile string, networks []string, extractor *dockermonitor.DockerMetadataExtractor, remoteEnforcer bool, killContainerError bool) (trireme.Trireme, monitor.Monitor) {

	// Load client cert
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		zap.L().Fatal(err.Error())
	}

	// Load key
	keyPEM, err := ioutil.ReadFile(keyFile)
	if err != nil {
		zap.L().Fatal(err.Error())
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		zap.L().Fatal("Failed to read key PEM")
	}

	// Load CA cert
	caCertPEM, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		zap.L().Fatal(err.Error())
	}

	policyEngine := NewCustomPolicyResolver(networks)

	t, m, p := configurator.NewPKITriremeWithDockerMonitor("Server1", policyEngine, ExternalProcessor, nil, false, keyPEM, certPEM, caCertPEM, *extractor, remoteEnforcer, killContainerError)

	if err := p.PublicKeyAdd("Server1", certPEM); err != nil {
		zap.L().Fatal(err.Error())
	}

	return t, m
}

//TriremeWithPSK is a helper method to created a PSK implementation of Trireme
func TriremeWithPSK(networks []string, extractor *dockermonitor.DockerMetadataExtractor, remoteEnforcer bool, killContainerError bool) (trireme.Trireme, monitor.Monitor) {

	policyEngine := NewCustomPolicyResolver(networks)

	// Use this if you want a pre-shared key implementation
	return configurator.NewPSKTriremeWithDockerMonitor("Server1", policyEngine, ExternalProcessor, nil, false, []byte("THIS IS A BAD PASSWORD"), *extractor, remoteEnforcer, killContainerError)
}

//HybridTriremeWithPSK is a helper method to created a PSK implementation of Trireme
func HybridTriremeWithPSK(networks []string, extractor *dockermonitor.DockerMetadataExtractor, killContainerError bool) (trireme.Trireme, monitor.Monitor, monitor.Monitor) {

	policyEngine := NewCustomPolicyResolver(networks)

	pass := []byte("THIS IS A BAD PASSWORD")
	// Use this if you want a pre-shared key implementation
	return configurator.NewPSKHybridTriremeWithMonitor("Server1", policyEngine, ExternalProcessor, nil, false, pass, *extractor, killContainerError)
}
