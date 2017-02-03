package common

import (
	"encoding/pem"
	"io/ioutil"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/configurator"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/dockermonitor"
	"github.com/aporeto-inc/trireme/supervisor"

	log "github.com/Sirupsen/logrus"
)

var (
	// ExternalProcessor to use if needed
	ExternalProcessor enforcer.PacketProcessor
)

// TriremeWithPKI is a helper method to created a PKI implementation of Trireme
func TriremeWithPKI(keyFile, certFile, caCertFile string, networks []string, extractor *dockermonitor.DockerMetadataExtractor, remoteEnforcer bool) (trireme.Trireme, monitor.Monitor, supervisor.Excluder) {

	// Load client cert
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		log.Fatal(err)
	}

	// Load key
	keyPEM, err := ioutil.ReadFile(keyFile)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		log.Fatalf("Failed to read key PEM ")
	}

	// Load CA cert
	caCertPEM, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		log.Fatalf("%s", err)
	}

	policyEngine := NewCustomPolicyResolver()

	t, m, e, p := configurator.NewPKITriremeWithDockerMonitor("Server1", networks, policyEngine, ExternalProcessor, nil, false, keyPEM, certPEM, caCertPEM, *extractor, remoteEnforcer)

	p.PublicKeyAdd("Server1", certPEM)

	return t, m, e
}

//TriremeWithPSK is a helper method to created a PSK implementation of Trireme
func TriremeWithPSK(networks []string, extractor *dockermonitor.DockerMetadataExtractor, remoteEnforcer bool) (trireme.Trireme, monitor.Monitor, supervisor.Excluder) {

	policyEngine := NewCustomPolicyResolver()

	// Use this if you want a pre-shared key implementation
	return configurator.NewPSKTriremeWithDockerMonitor("Server1", networks, policyEngine, ExternalProcessor, nil, false, []byte("THIS IS A BAD PASSWORD"), *extractor, remoteEnforcer)
}

//HybridTriremeWithPSK is a helper method to created a PSK implementation of Trireme
func HybridTriremeWithPSK(networks []string, extractor *dockermonitor.DockerMetadataExtractor) (trireme.Trireme, monitor.Monitor, monitor.Monitor, supervisor.Excluder) {

	policyEngine := NewCustomPolicyResolver()

	pass := []byte("THIS IS A BAD PASSWORD")
	// Use this if you want a pre-shared key implementation
	return configurator.NewPSKHybridTriremeWithMonitor("Server1", networks, policyEngine, ExternalProcessor, nil, false, pass, *extractor)
}
