package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/configurator"
	"github.com/aporeto-inc/trireme/monitor"
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

	usePKI := *flag.Bool("pki", false, "Use PKI trireme")
	certFile := *flag.String("certFile", "cert.pem", "Set the path of certificate.")
	keyFile := *flag.String("keyFile", "key.pem", "Set the path of key certificate key to use.")
	caCertFile := *flag.String("caCertFile", "ca.crt", "Set the path of certificate authority to use.")

	flag.Parse()

	var t trireme.Trireme
	var m monitor.Monitor

	if usePKI {
		t, m = triremeWithPKI(keyFile, certFile, caCertFile)
	} else {
		t, m = triremeWithPSK()
	}

	if t == nil {
		panic("Failed to create Trireme")
	}

	if m == nil {
		panic("Failed to create Monitor")
	}

	var wg sync.WaitGroup

	wg.Add(1)
	t.Start()
	m.Start()
	wg.Wait()
}

func triremeWithPKI(keyFile, certFile, caCertFile string) (trireme.Trireme, monitor.Monitor) {

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

func triremeWithPSK() (trireme.Trireme, monitor.Monitor) {

	networks := []string{"0.0.0.0/0"}
	policyEngine := NewCustomPolicyResolver()

	// Use this if you want a pre-shared key implementation
	return configurator.NewPSKTriremeWithDockerMonitor("Server1", networks, policyEngine, nil, false, []byte("THIS IS A BAD PASSWORD"))
}
