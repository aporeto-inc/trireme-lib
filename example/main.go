package main

import (
	"fmt"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/example/common"
	docopt "github.com/docopt/docopt-go"
)

func main() {

	usage := `Command for launching programs with Trireme policy.

  Usage:
    trireme -h | --help
    trireme --version
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
    trireme <cgroup>

  Options:
    -h --help                              Show this help message and exit.
    --version                              show version and exit.
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
    --target-networks=<networks>...        The target networks that Trireme should apply authentication [default: 172.17.0.0/24]
	<cgroup>                               cgroup of process.
  `

	arguments, _ := docopt.Parse(usage, nil, true, "1.0.0rc2", false)
	fmt.Println(arguments)

	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&log.TextFormatter{})

	common.ProcessArgs(arguments, nil)
}
