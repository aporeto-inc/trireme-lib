package monitor

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aporeto-inc/trireme/eventlog"
	"github.com/aporeto-inc/trireme/policy"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	dockerClient "github.com/docker/docker/client"

	"github.com/golang/glog"
)

func contextIDFromDockerID(dockerID string) (string, error) {

	if dockerID == "" {
		return "", fmt.Errorf("Empty DockerID String")
	}
	return dockerID[:12], nil
}

func initDockerClient(socketType string, socketAddress string) (*dockerClient.Client, error) {
	var socket string
	switch socketType {
	case "tcp":
		socket = "https://" + socketAddress

	case "unix":
		// Sanity check that this path exists
		if _, oserr := os.Stat(socketAddress); os.IsNotExist(oserr) {
			return nil, oserr
		}
		socket = "unix://" + socketAddress

	default:
		return nil, fmt.Errorf("Bad socket type %s", socketType)
	}

	defaultHeaders := map[string]string{"User-Agent": "engine-api-dockerClient-1.0"}
	dockerClient, err := dockerClient.NewClient(socket, "v1.23", nil, defaultHeaders)
	if err != nil {
		return nil, fmt.Errorf("Error creating Docker Client %s", err)
	}

	return dockerClient, nil
}

// dockerMonitor implements the connection to Docker and monitoring based on events
type dockerMonitor struct {
	dockerClient       *dockerClient.Client
	metadataExtractor  DockerMetadataExtractor
	handlers           map[string]func(event *events.Message) error
	eventnotifications chan *events.Message
	stopprocessor      chan bool
	stoplistener       chan bool
	syncAtStart        bool

	EventMonitor
}

// NewDockerMonitor returns a pointer to a DockerMonitor initialized with the given
// socketType ('tcp' or 'unix') and socketAddress (a port for 'tcp' or
// a socket file for 'unix').
//
// After creating a new DockerMonitor, call AddHandler to install one
// or more callback handlers for the events to monitor. Then call Start.
func NewDockerMonitor(
	socketType string,
	socketAddress string,
	p ProcessingUnitsHandler,
	m DockerMetadataExtractor,
	e eventlog.EventLogger,
	syncAtStart bool,
) (Monitor, error) {

	cli, err := initDockerClient(socketType, socketAddress)
	if err != nil {
		return nil, err
	}

	d := &dockerMonitor{
		EventMonitor: EventMonitor{
			PUHandler: p,
			Logger:    e,
		},
		syncAtStart:        syncAtStart,
		eventnotifications: make(chan *events.Message, 1000),
		handlers:           make(map[string]func(event *events.Message) error),
		stoplistener:       make(chan bool),
		stopprocessor:      make(chan bool),
		metadataExtractor:  m,
		dockerClient:       cli,
	}

	// Add handlers for the events that we know how to process
	d.AddHandler("start", d.handleStartEvent)
	d.AddHandler("die", d.handleDieEvent)
	d.AddHandler("destroy", d.handleDestroyEvent)
	d.AddHandler("connect", d.handleNetworkConnectEvent)

	return d, nil
}

// AddHandler adds a callback handler for the given docker event.
// Interesting event names include 'start' and 'die'. For more on events see
// https://docs.docker.com/engine/reference/api/docker_remote_api/
// under the section 'Docker Events'.
func (d *dockerMonitor) AddHandler(event string, handler func(event *events.Message) error) {
	d.handlers[event] = handler
}

// Start will start the DockerPolicy Enforcement.
// It applies a policy to each Container already Up and Running.
// It listens to all ContainerEvents
func (d *dockerMonitor) Start() error {
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
func (d *dockerMonitor) Stop() error {
	glog.Infoln("Stopping the docker monitor ...")
	d.stoplistener <- true
	d.stopprocessor <- true
	return nil
}

// eventProcessor processes docker events
func (d *dockerMonitor) eventProcessor() {

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
func (d *dockerMonitor) eventListener() {
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
func (d *dockerMonitor) syncContainers() error {
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

func (d *dockerMonitor) addOrUpdateDockerContainer(dockerInfo *types.ContainerJSON) error {

	timeout := time.Second * 0

	if !dockerInfo.State.Running {
		glog.V(2).Infoln("Container is not running - False alarm")
		return fmt.Errorf("Container not running - return error")
	}

	contextID, err := contextIDFromDockerID(dockerInfo.ID)
	if err != nil {
		return fmt.Errorf("Couldn't generate ContextID: %s", err)
	}

	runtimeInfo, err := d.extractMetadata(dockerInfo)

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

func (d *dockerMonitor) removeDockerContainer(dockerID string) error {
	contextID, err := contextIDFromDockerID(dockerID)
	if err != nil {
		return fmt.Errorf("Couldn't generate ContextID: %s", err)
	}

	return <-d.PUHandler.HandleDelete(contextID)
}

// ExtractMetadata generates the RuntimeInfo based on Docker primitive
func (d *dockerMonitor) extractMetadata(dockerInfo *types.ContainerJSON) (*policy.PURuntime, error) {

	if dockerInfo == nil {
		return nil, fmt.Errorf("DockerInfo is empty.")
	}

	if d.metadataExtractor != nil {
		return d.metadataExtractor.ExtractMetadata(dockerInfo)
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

// handleStartEvent will notify the agent immediately about the event in order
//to start the implementation of the functions. The agent must query
//the policy engine for details on what to do with this container.
func (d *dockerMonitor) handleStartEvent(event *events.Message) error {

	timeout := time.Second * 0
	id := event.ID

	info, err := d.dockerClient.ContainerInspect(context.Background(), id)
	if err != nil {
		glog.V(2).Infoln("Killing container because inspect returned error")
		//If we see errors, we will kill the container for security reasons.
		d.dockerClient.ContainerStop(context.Background(), id, &timeout)
		d.Logger.ContainerEvent(id[:12], "", nil, eventlog.ContainerFailed)
		return fmt.Errorf("Cannot read container information. Killing container. ")
	}

	if err := d.addOrUpdateDockerContainer(&info); err != nil {
		glog.V(2).Infof("Error while trying to add container: %s", err)
		return err
	}
	return nil
}

//handleDie event is called when a container dies. It updates the agent
//data structures and stops enforcement.
func (d *dockerMonitor) handleDieEvent(event *events.Message) error {

	containerID := event.ID

	d.removeDockerContainer(containerID)
	d.Logger.ContainerEvent(containerID[:12], "", nil, eventlog.ContainerStop)

	return nil
}

// handleDestroyEvent handles destroy events from Docker
func (d *dockerMonitor) handleDestroyEvent(event *events.Message) error {
	containerID := event.ID
	// Clear the policy cache
	d.PUHandler.HandleDelete(containerID[:12])
	d.Logger.ContainerEvent(containerID[:12], "", nil, eventlog.UnknownContainerDelete)

	return nil
}

func (d *dockerMonitor) handleNetworkConnectEvent(event *events.Message) error {

	id := event.Actor.Attributes["container"]

	container, err := d.dockerClient.ContainerInspect(context.Background(), id)
	if err != nil {
		glog.V(2).Infoln("Failed to read the affected container.")
	}
	glog.V(5).Infoln(container)
	return nil
}
