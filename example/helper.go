package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/policy"
)

// PolicyInfo holds the configuration of the policy engine
type PolicyInfo struct {
	cache map[string]policy.RuntimeGetter
}

// NewPolicyEngine creates a new policy engine for the Trireme package
func NewPolicyEngine(privateKeyPem, publicKeyPem, caCertificatePem []byte) *PolicyInfo {

	return &PolicyInfo{
		cache: map[string]policy.RuntimeGetter{},
	}
}

// CreateRuleDB creates a simple Rule DB that accepts packets from
// containers with the same labels as the instantiated container.
// If any of the labels matches, the packet is accepted.
func (p *PolicyInfo) createRules(runtimeInfo policy.RuntimeGetter) *policy.PUPolicy {

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
func (p *PolicyInfo) createSecrets(container *policy.PUInfo) error {

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	container.Policy.Extensions = key

	return nil

}

// GetPolicy implements the Trireme interface. Here we just create a simple
// policy that accepts packets with the same labels as the target container.
func (p *PolicyInfo) GetPolicy(context string, runtimeInfo policy.RuntimeGetter) (*policy.PUPolicy, error) {

	containerPolicyInfo := p.createRules(runtimeInfo)

	p.cache[context] = runtimeInfo
	containerPolicyInfo.PolicyTags = runtimeInfo.Tags()
	containerPolicyInfo.TriremeAction = policy.Police

	return containerPolicyInfo, nil
}

// DeletePU implements the corresponding interface. We have no
// state in this example
func (p *PolicyInfo) DeletePU(context string) error {
	return nil
}

// SetPolicyUpdater is used in order to register a pointer to the policyUpdater
func (p *PolicyInfo) SetPolicyUpdater(pu trireme.PolicyUpdater) error {
	return nil
}
