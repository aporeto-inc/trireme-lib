package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"

	"github.com/aporeto-inc/trireme/configurator"
	"github.com/pkg/profile"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: example -stderrthreshold=[INFO|WARN|FATAL] -log_dir=[string]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {

	defer profile.Start(profile.CPUProfile).Stop()

	flag.Usage = usage

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
	keyPool := map[string]*ecdsa.PublicKey{"Server1": &key.PublicKey}

	fmt.Println(keyPool)

	// Use this to use PKI Trireme
	trireme, monitor, pkadder := configurator.NewPKITriremeWithDockerMonitor("Server1", networks, policyEngine, nil, false, keyPEM, certPEM, caCertPEM)
	pkadder.PublicKeyAdd("Server1", certPEM)

	// Use this if you want a pre-shared key implementation
	// trireme, monitor = configurator.NewPSKTrireme("Server1", networks, policyEngine, svcImpl, false, []byte("THIS IS A BAD PASSWORD"))

	if trireme == nil {
		panic("Failed to create Trireme")
	}

	if monitor == nil {
		panic("Failed to create Monitor")
	}

	wg.Add(1)
	trireme.Start()
	monitor.Start()
	wg.Wait()
}
