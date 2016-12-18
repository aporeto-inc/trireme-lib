package common

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/configurator"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/extractor"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"

	log "github.com/Sirupsen/logrus"
)

// CustomPolicyResolver holds the configuration of the policy engine
type CustomPolicyResolver struct {
}

// NewCustomPolicyResolver creates a new policy engine for the Trireme package
func NewCustomPolicyResolver() *CustomPolicyResolver {

	return &CustomPolicyResolver{}
}

// ResolvePolicy implements the Trireme interface. Here we just create a simple
// policy that accepts packets with the same labels as the target container.
func (p *CustomPolicyResolver) ResolvePolicy(context string, runtimeInfo policy.RuntimeReader) (*policy.PUPolicy, error) {

	log.Infof("Getting Policy for ContainerID %s , name: %s ", context, runtimeInfo.Name())

	containerPolicyInfo := p.createRules(runtimeInfo)

	// Access google as an example of external ACL
	ingress := policy.NewIPRuleList([]policy.IPRule{
		policy.IPRule{
			Address:  "216.0.0.0/8",
			Port:     "80",
			Protocol: "TCP",
		},
	})

	// Allow access to container from localhost
	egress := policy.NewIPRuleList([]policy.IPRule{
		policy.IPRule{
			Address:  "172.17.0.1/32",
			Port:     "80",
			Protocol: "TCP",
		},
	})

	containerPolicyInfo.SetIngressACLs(ingress)
	containerPolicyInfo.SetEgressACLs(egress)

	// Use all the labels from Docker
	containerPolicyInfo.SetPolicyTags(runtimeInfo.Tags())

	// Use the bridge IP from Docker.
	ipl := policy.NewIPList([]string{})
	ip, ok := runtimeInfo.DefaultIPAddress()
	if ok {
		ipl.IPs = append(ipl.IPs, ip)
		containerPolicyInfo.SetIPAddresses(ipl)
	} else {
		containerPolicyInfo.SetIPAddresses(ipl)
	}

	// Police the container
	containerPolicyInfo.TriremeAction = policy.Police

	rules := containerPolicyInfo.ReceiverRules()
	for i, selector := range rules.TagSelectors {
		for _, clause := range selector.Clause {
			log.Infof("Trireme policy for container %s : Selector %d : %+v ", runtimeInfo.Name(), i, clause)
		}
	}

	return containerPolicyInfo, nil
}

// HandlePUEvent implements the corresponding interface. We have no
// state in this example
func (p *CustomPolicyResolver) HandlePUEvent(context string, eventType monitor.Event) {
	log.Infof("ContainerEvent %s, EventType: %s", context, eventType)
}

// SetPolicyUpdater is used in order to register a pointer to the policyUpdater
func (p *CustomPolicyResolver) SetPolicyUpdater(pu trireme.PolicyUpdater) error {
	return nil
}

// CreateRuleDB creates a simple Rule DB that accepts packets from
// containers with the same labels as the instantiated container.
// If any of the labels matches, the packet is accepted.
func (p *CustomPolicyResolver) createRules(runtimeInfo policy.RuntimeReader) *policy.PUPolicy {

	containerPolicyInfo := policy.NewPUPolicyWithDefaults()

	tags := runtimeInfo.Tags()
	for key, value := range tags.Tags {
		kv := policy.KeyValueOperator{
			Key:      key,
			Value:    []string{value},
			Operator: policy.Equal,
		}

		selector := policy.NewTagSelector([]policy.KeyValueOperator{kv}, policy.Accept)

		containerPolicyInfo.AddReceiverRules(selector)
	}
	return containerPolicyInfo

}

//TriremeWithPKI is a helper method to created a PKI implementation of Trireme
func TriremeWithPKI(keyFile, certFile, caCertFile string, networks []string, extractorPath string, remoteEnforcer bool) (trireme.Trireme, monitor.Monitor, supervisor.Excluder) {

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

	var bashExtractor monitor.DockerMetadataExtractor
	if extractorPath != "" {

		bashExtractor, err = extractor.NewExternalExtractor(extractorPath)
		if err != nil {
			fmt.Printf("error: ABC, %s", err)
		}
	}

	t, m, e, p := configurator.NewPKITriremeWithDockerMonitor("Server1", networks, policyEngine, nil, nil, false, keyPEM, certPEM, caCertPEM, bashExtractor, remoteEnforcer)

	p.PublicKeyAdd("Server1", certPEM)

	return t, m, e
}

//TriremeWithPSK is a helper method to created a PSK implementation of Trireme
func TriremeWithPSK(networks []string, extractorPath string, remoteEnforcer bool) (trireme.Trireme, monitor.Monitor, supervisor.Excluder) {

	policyEngine := NewCustomPolicyResolver()
	var bashExtractor monitor.DockerMetadataExtractor
	if extractorPath != "" {
		var err error
		bashExtractor, err = extractor.NewExternalExtractor(extractorPath)
		if err != nil {
			fmt.Printf("error: ABC, %s", err)
		}
	}

	// Use this if you want a pre-shared key implementation
	return configurator.NewPSKTriremeWithDockerMonitor("Server1", networks, policyEngine, nil, nil, false, []byte("THIS IS A BAD PASSWORD"), bashExtractor, remoteEnforcer)
}
