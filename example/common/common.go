package common

import (
	"encoding/pem"
	"io/ioutil"
	"log"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/configurator"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
)

// CustomPolicyResolver holds the configuration of the policy engine
type CustomPolicyResolver struct {
	cache map[string]policy.RuntimeReader
}

// NewCustomPolicyResolver creates a new policy engine for the Trireme package
func NewCustomPolicyResolver() *CustomPolicyResolver {

	return &CustomPolicyResolver{
		cache: map[string]policy.RuntimeReader{},
	}
}

// ResolvePolicy implements the Trireme interface. Here we just create a simple
// policy that accepts packets with the same labels as the target container.
func (p *CustomPolicyResolver) ResolvePolicy(context string, runtimeInfo policy.RuntimeReader) (*policy.PUPolicy, error) {

	containerPolicyInfo := p.createRules(runtimeInfo)

	p.cache[context] = runtimeInfo
	containerPolicyInfo.PolicyTags = runtimeInfo.Tags()
	containerPolicyInfo.TriremeAction = policy.Police

	return containerPolicyInfo, nil
}

// HandleDeletePU implements the corresponding interface. We have no
// state in this example
func (p *CustomPolicyResolver) HandleDeletePU(context string) error {
	return nil
}

// SetPolicyUpdater is used in order to register a pointer to the policyUpdater
func (p *CustomPolicyResolver) SetPolicyUpdater(pu trireme.PolicyUpdater) error {
	return nil
}

// CreateRuleDB creates a simple Rule DB that accepts packets from
// containers with the same labels as the instantiated container.
// If any of the labels matches, the packet is accepted.
func (p *CustomPolicyResolver) createRules(runtimeInfo policy.RuntimeReader) *policy.PUPolicy {

	containerPolicyInfo := policy.NewPUPolicy()

	for key, value := range runtimeInfo.Tags() {
		kv := policy.KeyValueOperator{
			Key:      key,
			Value:    []string{value},
			Operator: policy.Equal,
		}

		clause := []policy.KeyValueOperator{kv}

		selector := policy.TagSelector{
			Clause: clause,
			Action: policy.Accept,
		}

		containerPolicyInfo.Rules = append(containerPolicyInfo.Rules, selector)
	}
	return containerPolicyInfo

}

//TriremeWithPKI is a helper method to created a PKI implementation of Trireme
func TriremeWithPKI(keyFile, certFile, caCertFile string) (trireme.Trireme, monitor.Monitor) {

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
		log.Fatal("Failed to read key PEM ")
	}

	// Load CA cert
	caCertPEM, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		log.Fatal(err)
	}

	networks := []string{"0.0.0.0/0"}
	policyEngine := NewCustomPolicyResolver()

	t, m, p := configurator.NewPKITriremeWithDockerMonitor("Server1", networks, policyEngine, nil, false, keyPEM, certPEM, caCertPEM)

	p.PublicKeyAdd("Server1", certPEM)

	return t, m
}

//TriremeWithPSK is a helper method to created a PSK implementation of Trireme
func TriremeWithPSK() (trireme.Trireme, monitor.Monitor) {

	networks := []string{"0.0.0.0/0"}
	policyEngine := NewCustomPolicyResolver()

	// Use this if you want a pre-shared key implementation
	return configurator.NewPSKTriremeWithDockerMonitor("Server1", networks, policyEngine, nil, false, []byte("THIS IS A BAD PASSWORD"))
}
