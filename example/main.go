package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/cmd/remoteenforcer"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/example/common"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/cliextractor"
	"github.com/aporeto-inc/trireme/monitor/dockermonitor"

	log "github.com/Sirupsen/logrus"
)

var usePKI = flag.Bool("pki", false, "Use PKI trireme")
var certFile = flag.String("certFile", "cert.pem", "Set the path of certificate.")
var keyFile = flag.String("keyFile", "key.pem", "Set the path of key certificate key to use.")
var caCertFile = flag.String("caCertFile", "ca.crt", "Set the path of certificate authority to use.")
var externalMetadataFile = flag.String("metadata", "", "An external executable file for the metadata extractor")
var swarm = flag.String("swarm", "", "Support the Swarm Mode extractor")
var hybrid = flag.Bool("hybrid", false, "Hybrid mode")

func usage() {

	fmt.Fprintf(os.Stderr, "usage: example -stderrthreshold=[INFO|WARN|FATAL] -log_dir=[string]   -metadata=[string] -enforcer=[remote|local] -mode=[aporeto_enforcer|aporeto_service]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func init() {
	flag.StringVar(externalMetadataFile, "m", "", "Description")
}

func main() {

	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{})
	var remote string
	var mode string
	flag.Usage = usage

	flag.StringVar(&remote, "enforcer", "local", "Launch enforcer process in the network namespace of container")
	flag.StringVar(&mode, "mode", "aporeto_service", "Launch trireme as enforcer or service")
	flag.Parse()

	var t trireme.Trireme
	var m monitor.Monitor
	var rm monitor.Monitor
	//var e supervisor.Excluder
	var remoteEnforcer bool
	if mode == constants.DefaultRemoteArg {
		remoteenforcer.LaunchRemoteEnforcer()
	}

	if remote == "local" {
		remoteEnforcer = false
	} else {
		remoteEnforcer = true
	}

	var customExtractor dockermonitor.DockerMetadataExtractor
	if *externalMetadataFile != "" {
		var err error
		customExtractor, err = cliextractor.NewExternalExtractor(*externalMetadataFile)
		if err != nil {
			fmt.Printf("error: ABC, %s", err)
		}
	}

	if *swarm == "true" {
		log.WithFields(log.Fields{
			"Package":   "main",
			"Extractor": "Swarm",
		}).Debug("Using Docker Swarm extractor")
		customExtractor = common.SwarmExtractor
	}

	if !*hybrid {
		if *usePKI {
			log.Infof("Setting up trireme with PKI")
			t, m, _ = common.TriremeWithPKI(*keyFile, *certFile, *caCertFile, []string{"172.17.0.0/24", "10.0.0.0/8"}, &customExtractor, remoteEnforcer)
		} else {
			log.Infof("Setting up trireme with PSK")
			t, m, _ = common.TriremeWithPSK([]string{"172.17.0.0/24", "10.0.0.0/8"}, &customExtractor, remoteEnforcer)
		}
	} else {
		t, m, rm, _ = common.HybridTriremeWithPSK([]string{"172.17.0.0/24", "10.0.0.0/8"}, &customExtractor, remoteEnforcer)
	}

	if t == nil {
		panic("Failed to create Trireme")
	}

	if m == nil {
		panic("Failed to create Monitor")
	}

	if *hybrid && rm == nil {
		panic("Failed to create remote monitor for hybrid")
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	t.Start()
	m.Start()
	if rm != nil {
		rm.Start()
	}

	<-c

	fmt.Println("Bye!")
	m.Stop()
	t.Stop()
	if rm != nil {
		rm.Stop()
	}

}
