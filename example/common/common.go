package common

import (
	"context"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/configurator"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"
	"github.com/docker/docker/api/types"
	dockerClient "github.com/docker/docker/client"

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

	tagSelectors := p.createRules(runtimeInfo)

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

	// Use the bridge IP from Docker.
	ipl := policy.NewIPMap(map[string]string{})
	if ip, ok := runtimeInfo.DefaultIPAddress(); ok {
		ipl.IPs[policy.DefaultNamespace] = ip
	}

	identity := runtimeInfo.Tags()

	annotations := runtimeInfo.Tags()

	containerPolicyInfo := policy.NewPUPolicy(context, policy.Police, ingress, egress, nil, tagSelectors, identity, annotations, ipl, nil)

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
func (p *CustomPolicyResolver) createRules(runtimeInfo policy.RuntimeReader) *policy.TagSelectorList {

	selectorList := &policy.TagSelectorList{
		TagSelectors: []policy.TagSelector{},
	}

	tags := runtimeInfo.Tags()
	for key, value := range tags.Tags {
		kv := policy.KeyValueOperator{
			Key:      key,
			Value:    []string{value},
			Operator: policy.Equal,
		}

		tagSelector := policy.NewTagSelector([]policy.KeyValueOperator{kv}, policy.Accept)
		selectorList.TagSelectors = append(selectorList.TagSelectors, *tagSelector)

	}

	for i, selector := range selectorList.TagSelectors {
		for _, clause := range selector.Clause {
			log.Infof("Trireme policy for container %s : Selector %d : %+v ", runtimeInfo.Name(), i, clause)
		}
	}
	return selectorList

}

//TriremeWithPKI is a helper method to created a PKI implementation of Trireme
func TriremeWithPKI(keyFile, certFile, caCertFile string, networks []string, extractor *monitor.DockerMetadataExtractor, remoteEnforcer bool) (trireme.Trireme, monitor.Monitor, supervisor.Excluder) {

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

	t, m, e, p := configurator.NewPKITriremeWithDockerMonitor("Server1", networks, policyEngine, nil, nil, false, keyPEM, certPEM, caCertPEM, *extractor, remoteEnforcer)

	p.PublicKeyAdd("Server1", certPEM)

	return t, m, e
}

//TriremeWithPSK is a helper method to created a PSK implementation of Trireme
func TriremeWithPSK(networks []string, extractor *monitor.DockerMetadataExtractor, remoteEnforcer bool) (trireme.Trireme, monitor.Monitor, supervisor.Excluder) {

	policyEngine := NewCustomPolicyResolver()

	// Use this if you want a pre-shared key implementation
	return configurator.NewPSKTriremeWithDockerMonitor("Server1", networks, policyEngine, nil, nil, false, []byte("THIS IS A BAD PASSWORD"), *extractor, remoteEnforcer)
}

// SwarmExtractor is an example metadata extractor for swarm that uses the service
// labels for policy decisions
func SwarmExtractor(info *types.ContainerJSON) (*policy.PURuntime, error) {

	// Create a docker client
	defaultHeaders := map[string]string{"User-Agent": "engine-api-dockerClient-1.0"}
	cli, err := dockerClient.NewClient("unix:///var/run/docker.sock", "v1.23", nil, defaultHeaders)
	if err != nil {
		log.WithFields(log.Fields{
			"Package": "main",
			"error":   err.Error(),
		}).Debug("Failed to open docker connection")

		return nil, fmt.Errorf("Error creating Docker Client %s", err)
	}

	// Get the labels from Docker. If it is a swarm service, get the labels from
	// the service definition instead.
	dockerLabels := info.Config.Labels
	if _, ok := info.Config.Labels["com.docker.swarm.service.id"]; ok {

		serviceID := info.Config.Labels["com.docker.swarm.service.id"]

		service, _, err := cli.ServiceInspectWithRaw(context.Background(), serviceID)
		if err != nil {
			log.WithFields(log.Fields{
				"Package": "main",
				"error":   err.Error(),
			}).Debug("Failed get swarm labels")
			return nil, fmt.Errorf("Error creating Docker Client %s", err)
		}

		dockerLabels = service.Spec.Labels
	}

	// Create the tags based on the docker labels
	tags := policy.NewTagsMap(map[string]string{
		"image": info.Config.Image,
		"name":  info.Name,
	})
	for k, v := range dockerLabels {
		tags.Add(k, v)
	}

	ipa := policy.NewIPMap(map[string]string{
		"bridge": info.NetworkSettings.IPAddress,
	})

	return policy.NewPURuntime(info.Name, info.State.Pid, tags, ipa), nil
}
