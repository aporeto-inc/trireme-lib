package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/example/common"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/extractor"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/docker/docker/api/types"
	dockerClient "github.com/docker/docker/client"

	log "github.com/Sirupsen/logrus"
)

var usePKI = flag.Bool("pki", false, "Use PKI trireme")
var certFile = flag.String("certFile", "cert.pem", "Set the path of certificate.")
var keyFile = flag.String("keyFile", "key.pem", "Set the path of key certificate key to use.")
var caCertFile = flag.String("caCertFile", "ca.crt", "Set the path of certificate authority to use.")
var externalMetadataFile = flag.String("metadata", "", "An external executable file for the metadata extractor")
var swarm = flag.String("swarm", "", "Support the Swarm Mode extractor")

func usage() {

	fmt.Fprintf(os.Stderr, "usage: example -stderrthreshold=[INFO|WARN|FATAL] -log_dir=[string]   -metadata=[string] -enforcer=[remote|local]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func init() {
	flag.StringVar(externalMetadataFile, "m", "", "Description")
}

// swarmExtractor is an example metadata extractor for swarm that uses the service
// labels for policy decisions
func swarmExtractor(info *types.ContainerJSON) (*policy.PURuntime, error) {

	// Create a docker client
	defaultHeaders := map[string]string{"User-Agent": "engine-api-dockerClient-1.0"}
	cli, err := dockerClient.NewClient("unix:///var/run/docker.sock", "v1.23", nil, defaultHeaders)
	if err != nil {
		log.WithFields(log.Fields{
			"Package": "main",
			"error":   err.Error(),
		}).Debug("Failed to open docker connection")

		return nil, fmt.Errorf("Error creating Docker Client %s", err)
	}

	// Get the labels from Docker. If it is a swarm service, get the labels from
	// the service definition instead.
	dockerLabels := info.Config.Labels
	if _, ok := info.Config.Labels["com.docker.swarm.service.id"]; ok {

		serviceID := info.Config.Labels["com.docker.swarm.service.id"]

		service, _, err := cli.ServiceInspectWithRaw(context.Background(), serviceID)
		if err != nil {
			log.WithFields(log.Fields{
				"Package": "main",
				"error":   err.Error(),
			}).Debug("Failed get swarm labels")
			return nil, fmt.Errorf("Error creating Docker Client %s", err)
		}

		dockerLabels = service.Spec.Labels
	}

	// Create the tags based on the docker labels
	tags := policy.NewTagsMap(map[string]string{
		"image": info.Config.Image,
		"name":  info.Name,
	})
	for k, v := range dockerLabels {
		tags.Add(k, v)
	}

	ipa := policy.NewIPMap(map[string]string{
		"bridge": info.NetworkSettings.IPAddress,
	})

	return policy.NewPURuntime(info.Name, info.State.Pid, tags, ipa), nil
}

func main() {

	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{})
	var remote string

	flag.Usage = usage

	flag.StringVar(&remote, "enforcer", "local", "Launch enforcer process in the network namespace of container")

	flag.Parse()

	var t trireme.Trireme
	var m monitor.Monitor
	//var e supervisor.Excluder
	var remoteEnforcer bool

	if remote == "local" {
		remoteEnforcer = false
	} else {
		remoteEnforcer = true
	}

	var customExtractor monitor.DockerMetadataExtractor
	if *externalMetadataFile != "" {
		var err error
		customExtractor, err = extractor.NewExternalExtractor(*externalMetadataFile)
		if err != nil {
			fmt.Printf("error: ABC, %s", err)
		}
	}

	if *swarm == "true" {
		log.WithFields(log.Fields{
			"Package":   "main",
			"Extractor": "Swarm",
		}).Debug("Using Docker Swarm extractor")
		customExtractor = swarmExtractor
	}

	if *usePKI {
		log.Infof("Setting up trireme with PKI")
		t, m, _ = common.TriremeWithPKI(*keyFile, *certFile, *caCertFile, []string{"172.17.0.0/24", "10.0.0.0/8"}, &customExtractor, remoteEnforcer)
	} else {
		log.Infof("Setting up trireme with PSK")
		t, m, _ = common.TriremeWithPSK([]string{"172.17.0.0/24", "10.0.0.0/8"}, &customExtractor, remoteEnforcer)

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
