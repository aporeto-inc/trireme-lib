package monitor

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aporeto-inc/trireme/eventlog"
	"github.com/aporeto-inc/trireme/interfaces"
	"github.com/aporeto-inc/trireme/policy"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	dockerClient "github.com/docker/docker/client"

	"github.com/golang/glog"
)

// Docker implements the connection to Docker and monitoring based on events
type Docker struct {
	EventMonitor
	dockerClient       *dockerClient.Client
	metadataExtractor  interfaces.DockerMetadataExtractor
	handlers           map[string]func(event *events.Message) error
	eventnotifications chan *events.Message
	stopprocessor      chan bool
	stoplistener       chan bool
	syncAtStart        bool
}

// NewDockerMonitor returns a pointer to a DockerMonitor initialized with the given
// socketType ('tcp' or 'unix') and socketAddress (a port for 'tcp' or
// a socket file for 'unix').
//
// After creating a new DockerMonitor, call AddHandler to install one
// or more callback handlers for the events to monitor. Then call Start.
func NewDockerMonitor(socketType string, socketAddress string, p interfaces.ProcessingUnitsHandler, m interfaces.DockerMetadataExtractor, e eventlog.EventLogger, syncAtStart bool) (docker *Docker, err error) {
	var d Docker

	if d.initDockerClient(socketType, socketAddress) != nil {
		return nil, err
	}

	// register the base objects for callbacks
	d.PUHandler = p
	d.Logger = e
	d.syncAtStart = syncAtStart

	d.eventnotifications = make(chan *events.Message, 1000)
	d.handlers = make(map[string]func(event *events.Message) error)
	d.stoplistener = make(chan bool)
	d.stopprocessor = make(chan bool)

	if m == nil {
		d.metadataExtractor = &d
	} else {
		d.metadataExtractor = m
	}

	// Add handlers for the events that we know how to process
	d.AddHandler("start", d.handleStartEvent)
	d.AddHandler("die", d.handleDieEvent)
	d.AddHandler("destroy", d.handleDestroyEvent)
	d.AddHandler("connect", d.handleNetworkConnectEvent)

	return &d, nil
}

func (d *Docker) initDockerClient(socketType string, socketAddress string) (err error) {
	var socket string
	switch socketType {
	case "tcp":
		socket = "https://" + socketAddress

	case "unix":
		// Sanity check that this path exists
		if _, oserr := os.Stat(socketAddress); os.IsNotExist(oserr) {
			return err
		}
		socket = "unix://" + socketAddress

	default:
		return fmt.Errorf("Bad socket type %s", socketType)
	}

	defaultHeaders := map[string]string{"User-Agent": "engine-api-dockerClient-1.0"}
	d.dockerClient, err = dockerClient.NewClient(socket, "v1.23", nil, defaultHeaders)
	if err != nil {
		return fmt.Errorf("Error creating Docker Client %s", err)
	}
	return nil
}

// AddHandler adds a callback handler for the given docker event.
// Interesting event names include 'start' and 'die'. For more on events see
// https://docs.docker.com/engine/reference/api/docker_remote_api/
// under the section 'Docker Events'.
func (d *Docker) AddHandler(event string, handler func(event *events.Message) error) {
	d.handlers[event] = handler
}

// Start will start the DockerPolicy Enforcement.
// It applies a policy to each Container already Up and Running.
// It listens to all ContainerEvents
func (d *Docker) Start() error {
	glog.Infoln("Starting the docker monitor ...")

	// Starting the eventListener First.
	go d.eventListener()

	//Syncing all Existing containers depending on MonitorSetting
	if d.syncAtStart {
		err := d.syncContainers()
		if err != nil {
			glog.V(1).Infoln("Error Syncing existingContainers: %s", err)
		}
	}

	// Processing the events received duringthe time of Sync.
	go d.eventProcessor()
	return nil
}

// Stop monitoring docker events.
func (d *Docker) Stop() error {
	glog.Infoln("Stopping the docker monitor ...")
	d.stoplistener <- true
	d.stopprocessor <- true
	return nil
}

// eventProcessor processes docker events
func (d *Docker) eventProcessor() {

	for {
		select {
		case event := <-d.eventnotifications:
			if event.Action != "" {
				f, present := d.handlers[event.Action]
				if present {
					glog.V(1).Infof("Handling docker event [%s].", event.Action)
					f(event)
				} else {
					glog.V(2).Infof("Docker event [%s] not handled.", event.Action)
				}
			}
		case <-d.stopprocessor:
			return
		}
	}
}

// eventListener listens to Docker events from the daemon and passes to
// to the processor through a buffered channel. This minimizes the chances
// that we will miss events because the processor is delayed
func (d *Docker) eventListener() {
	messages, errs := d.dockerClient.Events(context.Background(), types.EventsOptions{})

	for {
		select {
		case message := <-messages:
			d.eventnotifications <- &message
		case err := <-errs:
			if err != nil && err != io.EOF {
				glog.V(1).Infoln("Received docer event error ", err)
			}
		case stop := <-d.stoplistener:
			if stop {
				return
			}
		}
	}
}

// syncContainers resyncs all the existing containers on the Host, using the
// same process as when a container is initially spawn up
func (d *Docker) syncContainers() error {
	glog.Infoln("Syncing all existing containers")

	options := types.ContainerListOptions{All: true}
	containers, err := d.dockerClient.ContainerList(context.Background(), options)
	if err != nil {
		return err
	}

	for _, c := range containers {
		container, err := d.dockerClient.ContainerInspect(context.Background(), c.ID)
		if err != nil {
			glog.V(1).Infoln("Error Syncing existing Container: %s", err)
		}
		if err := d.addOrUpdateDockerContainer(&container); err != nil {
			glog.V(1).Infoln("Error Syncing existing Container: %s", err)
		}
	}
	return nil
}

// DockerMetadataExtract generates the RuntimeInfo based on Docker primitive
func (d *Docker) DockerMetadataExtract(dockerInfo *types.ContainerJSON) (*policy.PURuntime, error) {
	if dockerInfo == nil {
		return nil, fmt.Errorf("DockerInfo is empty.")
	}

	runtimeInfo := policy.NewPURuntime()

	runtimeInfo.SetName(dockerInfo.Name)
	runtimeInfo.SetPid(dockerInfo.State.Pid)
	ipa := map[string]string{}
	ipa["bridge"] = dockerInfo.NetworkSettings.IPAddress
	runtimeInfo.SetIPAddresses(ipa)
	tags := policy.TagMap{}
	tags["image"] = dockerInfo.Config.Image
	tags["name"] = dockerInfo.Name
	for k, v := range dockerInfo.Config.Labels {
		tags[k] = v
	}
	runtimeInfo.SetTags(tags)
	return runtimeInfo, nil
}

func contextIDFromDockerID(dockerID string) (string, error) {
	if dockerID == "" {
		return "", fmt.Errorf("Empty DockerID String")
	}
	return dockerID[:12], nil
}

func (d *Docker) addOrUpdateDockerContainer(dockerInfo *types.ContainerJSON) error {

	timeout := time.Second * 0

	if !dockerInfo.State.Running {
		glog.V(2).Infoln("Container is not running - False alarm")
		return fmt.Errorf("Container not running - return error")
	}

	contextID, err := contextIDFromDockerID(dockerInfo.ID)
	if err != nil {
		return fmt.Errorf("Couldn't generate ContextID: %s", err)
	}

	runtimeInfo, err := d.DockerMetadataExtract(dockerInfo)

	if err != nil {
		return fmt.Errorf("Error getting some of the Docker primitives")
	}

	ip, ok := runtimeInfo.DefaultIPAddress()
	if !ok || ip == "" {
		return fmt.Errorf("IP Not present in container, not policing")
	}

	returnChan := d.PUHandler.HandleCreate(contextID, runtimeInfo)
	if err := <-returnChan; err != nil {
		glog.V(2).Infoln("Setting policy failed. Stopping the container")
		d.dockerClient.ContainerStop(context.Background(), dockerInfo.ID, &timeout)
		d.Logger.ContainerEvent(contextID, ip, nil, eventlog.ContainerFailed)
		return fmt.Errorf("Policy cound't be set - container was killed")
	}

	d.Logger.ContainerEvent(contextID, ip, runtimeInfo.Tags(), eventlog.ContainerStart)
	return nil
}

func (d *Docker) removeDockerContainer(dockerID string) error {
	contextID, err := contextIDFromDockerID(dockerID)
	if err != nil {
		return fmt.Errorf("Couldn't generate ContextID: %s", err)
	}

	return <-d.PUHandler.HandleDelete(contextID)
}
