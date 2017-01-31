package main

import (
	"fmt"
	"os"
	"os/signal"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/cmd/remoteenforcer"
	"github.com/aporeto-inc/trireme/cmd/systemdutil"
	"github.com/aporeto-inc/trireme/example/common"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/cliextractor"
	"github.com/aporeto-inc/trireme/monitor/dockermonitor"
	docopt "github.com/docopt/docopt-go"
)

func main() {

	usage := `Command for launching programs with Trireme policy.

  Usage:
    trireme run
      [--service-name=<sname>]
      [[--label=<keyvalue>]...]
      [--ports=<ports>]
      <command> [--] [<params>...]
    trireme daemon
      [--target-networks=<networks>...]
      [--usePKI]
      [--hybrid|--remote|--local]
      [--swarm|--extractor <metadatafile>]
      [--keyFile=<keyFile>]
      [--certFile=<certFile>]
      [--caCert=<caFile>]
    trireme enforce
    trireme  <cgroup>
    trireme -h | --help
    trireme --version

  Options:
    -h --help                              Show this help message and exit.
    --service-name=<sname>                 The name of the service to be launched.
    --label=<keyvalue>                     The metadata/labels associated with a service.
    --usePKI                               Use PKI for Trireme [default: false].
    --certFile=<certfile>                  Certificate file [default: cert.pem].
    --keyFile=<keyFile>                    Key file [default: key.pem].
    --caCert=<caFile>                      CA certificate [default: ca.crt].
    --hybrid                               Hybrid mode of deployment [default: false]
    --remote                               Remote mode of deployment [default: false]
    --local                                Local mode of deployment [default: true]
    --swarm                                Deploy Doccker Swarm metadata extractor [default: false]
    --extractor                            External metadata extractor [default: ]
    --version                              show version and exit.
    --target-networks=<networks>...        The target networks that Trireme should apply authentication [default: 172.17.0.0/24]
  `

	arguments, _ := docopt.Parse(usage, nil, true, "1.0.0rc2", false)
	fmt.Println(arguments)

	var t trireme.Trireme
	var m monitor.Monitor
	var rm monitor.Monitor
	var err error

	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&log.TextFormatter{})

	// If in enforce mode then just launch in this mode and exit
	if arguments["enforce"].(bool) {
		remoteenforcer.LaunchRemoteEnforcer()
	}

	if arguments["run"].(bool) || arguments["<cgroup>"] != nil {
		systemdutil.ExecuteCommand(arguments)
	}

	if !arguments["daemon"].(bool) {
		os.Exit(0)
	}

	var customExtractor dockermonitor.DockerMetadataExtractor

	if arguments["--extractor"].(bool) {
		extractorfile := arguments["<metadatafile>"].(string)
		customExtractor, err = cliextractor.NewExternalExtractor(extractorfile)
		if err != nil {
			log.Fatalf("External metadata extractor cannot be accessed: %s", err)
		}
	}

	if arguments["--swarm"].(bool) {
		log.WithFields(log.Fields{
			"Package":   "main",
			"Extractor": "Swarm",
		}).Debug("Using Docker Swarm extractor")
		customExtractor = common.SwarmExtractor
	}

	targetNetworks := []string{"172.17.0.0/24", "10.0.0.0/8"}
	if len(arguments["--target-networks"].([]string)) > 0 {
		log.WithFields(log.Fields{
			"Package":         "main",
			"target networks": arguments["--target-networks"].([]string),
		}).Info("Target Networks")
		targetNetworks = arguments["--target-networks"].([]string)
	}

	if !arguments["--hybrid"].(bool) {
		remote := arguments["--remote"].(bool)
		if arguments["--usePKI"].(bool) {
			log.Infof("Setting up trireme with PKI")

			keyFile := arguments["--keyFile"].(string)
			certFile := arguments["--certFile"].(string)
			caCertFile := arguments["--caCert"].(string)

			t, m, _ = common.TriremeWithPKI(keyFile, certFile, caCertFile, targetNetworks, &customExtractor, remote)

		} else {

			log.Infof("Setting up trireme with PSK")
			t, m, _ = common.TriremeWithPSK(targetNetworks, &customExtractor, remote)

		}
	} else { // Hybrid mode
		t, m, rm, _ = common.HybridTriremeWithPSK(targetNetworks, &customExtractor)
	}

	if t == nil {
		log.Fatalln("Failed to create Trireme")
	}

	if m == nil {
		log.Fatalln("Failed to create Monitor")
	}

	if arguments["--hybrid"].(bool) && rm == nil {
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
