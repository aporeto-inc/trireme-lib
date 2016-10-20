package helper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/datapath"
	"github.com/aporeto-inc/trireme/interfaces"
	"github.com/aporeto-inc/trireme/policy"
)

// PolicyInfo holds the configuration of the policy engine
type PolicyInfo struct {
	cache map[string]interfaces.RuntimeGetter
}

// NewPolicyEngine creates a new policy engine for the Trireme package
func NewPolicyEngine(privateKeyPem, publicKeyPem, caCertificatePem []byte) *PolicyInfo {

	return &PolicyInfo{
		cache: map[string]interfaces.RuntimeGetter{},
	}
}

// CreateRuleDB creates a simple Rule DB that accepts packets from
// containers with the same labels as the instantiated container.
// If any of the labels matches, the packet is accepted.
func (p *PolicyInfo) createRules(runtimeInfo interfaces.RuntimeGetter) *policy.PUPolicy {

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
func (p *PolicyInfo) GetPolicy(context string, runtimeInfo interfaces.RuntimeGetter) (*policy.PUPolicy, error) {

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
func (p *PolicyInfo) SetPolicyUpdater(pu interfaces.PolicyUpdater) error {
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: example -stderrthreshold=[INFO|WARN|FATAL] -log_dir=[string]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

// New starts a new example
func New(svcImpl datapath.Service) {

	var keyFile, certFile, caCertFile string
	var wg sync.WaitGroup
	var err error

	flag.StringVar(&keyFile, "keyFile", "key.pem", "-keyFile")
	flag.StringVar(&certFile, "certFile", "cert.pem", "-certFile")
	flag.StringVar(&caCertFile, "caCertFile", "ca.crt", "ca.crt default")

	flag.Parse()

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

	// Parse the key
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("Failed to read private key ")
	}

	// Load CA cert
	caCertPEM, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		log.Fatal(err)
	}

	networks := []string{"0.0.0.0/0"}

	policyEngine := NewPolicyEngine(keyPEM, certPEM, caCertPEM)

	keyPool := map[string]*ecdsa.PublicKey{
		"Server1": &key.PublicKey,
	}

	fmt.Println(keyPool)

	var helper *trireme.Helper
	if true {

		helper = trireme.NewPKITrireme("Server1", networks, policyEngine, svcImpl, false, keyPEM, certPEM, caCertPEM)
	} else {
		// Change this to below if you want a pre-shared key implementation
		helper = trireme.NewPSKTrireme("Server1", networks, policyEngine, svcImpl, false, []byte("THIS IS A BAD PASSWORD"))
	}

	if helper == nil {
		panic("Failed to create helper")
	}

	wg.Add(2)
	helper.PkAdder.PublicKeyAdd("Server1", certPEM)
	helper.Trireme.Start()
	helper.Monitor.Start()
	wg.Wait()
	return
}
