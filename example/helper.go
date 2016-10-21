package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/aporeto-inc/trireme"
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

// createSecrets will create the per-container secrets and associated them with
// the policy
func (p *CustomPolicyResolver) createSecrets(container *policy.PUInfo) error {

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	container.Policy.Extensions = key

	return nil

}
