package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/cmd/remoteenforcer"
	"github.com/aporeto-inc/trireme/example/common"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/cliextractor"
	"github.com/aporeto-inc/trireme/monitor/dockermonitor"

	log "github.com/Sirupsen/logrus"
)

var (
	usePKI               = flag.Bool("pki", false, "Use PKI trireme")
	hybrid               = flag.Bool("hybrid", false, "Hybrid mode")
	remote               = flag.Bool("remote", false, "Use remote enforcers")
	swarm                = flag.Bool("swarm", false, "Support the Swarm Mode extractor")
	certFile             = flag.String("certFile", "cert.pem", "Set the path of certificate.")
	keyFile              = flag.String("keyFile", "key.pem", "Set the path of key certificate key to use.")
	caCertFile           = flag.String("caCertFile", "ca.crt", "Set the path of certificate authority to use.")
	externalMetadataFile = flag.String("metadata", "", "An external executable file for the metadata extractor")
	mode                 = flag.String("mode", "service", "Launch trireme as a service or enforcement only")
)

func usage() {
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {

	var t trireme.Trireme
	var m monitor.Monitor
	var rm monitor.Monitor
	var err error

	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{})

	flag.Usage = usage

	flag.Parse()

	// If in enforce mode then just launch in this mode and exit
	if *mode == "enforce" {
		remoteenforcer.LaunchRemoteEnforcer()
	}

	var customExtractor dockermonitor.DockerMetadataExtractor

	if *externalMetadataFile != "" && *swarm == true {
		log.Fatalln("Only provide an external extractor or swarm, but not both.")
	}

	if *externalMetadataFile != "" {
		customExtractor, err = cliextractor.NewExternalExtractor(*externalMetadataFile)
		if err != nil {
			log.Fatalf("External metadata extractor cannot be accessed: %s", err)
		}
	}

	if *swarm == true {
		log.WithFields(log.Fields{
			"Package":   "main",
			"Extractor": "Swarm",
		}).Debug("Using Docker Swarm extractor")
		customExtractor = common.SwarmExtractor
	}

	if !*hybrid {
		if *usePKI {
			log.Infof("Setting up trireme with PKI")
			t, m, _ = common.TriremeWithPKI(*keyFile, *certFile, *caCertFile, []string{"172.17.0.0/24", "10.0.0.0/8"}, &customExtractor, *remote)
		} else {
			log.Infof("Setting up trireme with PSK")
			t, m, _ = common.TriremeWithPSK([]string{"172.17.0.0/24", "10.0.0.0/8"}, &customExtractor, *remote)
		}
	} else { // Hybrid mode
		t, m, rm, _ = common.HybridTriremeWithPSK([]string{"172.17.0.0/24", "10.0.0.0/8"}, &customExtractor, *remote)
	}

	if t == nil {
		log.Fatalln("Failed to create Trireme")
	}

	if m == nil {
		log.Fatalln("Failed to create Monitor")
	}

	if *hybrid && rm == nil {
		log.Fatalln("Failed to create remote monitor for hybrid")
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// Start services
	t.Start()
	m.Start()
	if rm != nil {
		rm.Start()
	}

	// Wait for Ctrl-C
	<-c

	fmt.Println("Bye!")
	m.Stop()
	t.Stop()
	if rm != nil {
		rm.Stop()
	}
}
