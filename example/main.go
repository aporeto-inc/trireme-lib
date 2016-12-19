package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/example/common"
	"github.com/aporeto-inc/trireme/monitor"

	log "github.com/Sirupsen/logrus"
)

var usePKI = flag.Bool("pki", false, "Use PKI trireme")
var certFile = flag.String("certFile", "cert.pem", "Set the path of certificate.")
var keyFile = flag.String("keyFile", "key.pem", "Set the path of key certificate key to use.")
var caCertFile = flag.String("caCertFile", "ca.crt", "Set the path of certificate authority to use.")
var externalMetadataFile = flag.String("metadata", "", "An external executable file for the metadata extractor")

func usage() {
	fmt.Fprintf(os.Stderr, "usage: example -stderrthreshold=[INFO|WARN|FATAL] -log_dir=[string] -metadata=[string]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func init() {
	flag.StringVar(externalMetadataFile, "m", "", "Description")
}

func main() {

	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{})

	flag.Usage = usage

	flag.Parse()

	var t trireme.Trireme
	var m monitor.Monitor

	if *usePKI {
		log.Infof("Setting up trireme with PKI")
		t, m, _ = common.TriremeWithPKI(*keyFile, *certFile, *caCertFile, []string{"172.0.0.0/24"}, *externalMetadataFile)
	} else {
		log.Infof("Setting up trireme with PSK")
		t, m, _ = common.TriremeWithPSK([]string{"172.0.0.0/24"}, *externalMetadataFile)
	}

	if t == nil {
		panic("Failed to create Trireme")
	}

	if m == nil {
		panic("Failed to create Monitor")
	}

	t.Start()
	m.Start()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	fmt.Println("Bye!")
	m.Stop()
	t.Stop()
}
