package monitor

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"

	dockerClient "github.com/docker/docker/client"
)

// DockerEvent is the type of various docker events.
type DockerEvent string

const (
	// DockerEventCreate represents the Docker "create" event.
	DockerEventCreate DockerEvent = "create"

	// DockerEventStart represents the Docker "start" event.
	DockerEventStart DockerEvent = "start"

	// DockerEventDie represents the Docker "die" event.
	DockerEventDie DockerEvent = "die"

	// DockerEventDestroy represents the Docker "destroy" event.
	DockerEventDestroy DockerEvent = "destroy"

	// DockerEventPause represents the Docker "destroy" event.
	DockerEventPause DockerEvent = "pause"

	// DockerEventUnpause represents the Docker "destroy" event.
	DockerEventUnpause DockerEvent = "unpause"

	// DockerEventConnect represents the Docker "connect" event.
	DockerEventConnect DockerEvent = "connect"

	// DockerClientVersion is the version sent out as the client
	DockerClientVersion = "v1.23"
)

// A DockerEventHandler is type of docker event handler functions.
type DockerEventHandler func(event *events.Message) error

// A DockerMetadataExtractor is a function used to extract a *policy.PURuntime from a given
// docker ContainerJSON.
type DockerMetadataExtractor func(*types.ContainerJSON) (*policy.PURuntime, error)

func contextIDFromDockerID(dockerID string) (string, error) {

	if dockerID == "" {
		return "", fmt.Errorf("Empty DockerID String")
	}

	if len(dockerID) < 12 {
		return "", fmt.Errorf("dockerID smaller than 12 characters")
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
	dockerClient, err := dockerClient.NewClient(socket, DockerClientVersion, nil, defaultHeaders)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "monitor",
			"error":   err.Error(),
		}).Debug("Error creating Docker Client")

		return nil, fmt.Errorf("Error creating Docker Client %s", err)
	}

	return dockerClient, nil
}

func defaultDockerMetadataExtractor(info *types.ContainerJSON) (*policy.PURuntime, error) {

	tags := policy.NewTagsMap(map[string]string{
		"image": info.Config.Image,
		"name":  info.Name,
	})
	for k, v := range info.Config.Labels {
		tags.Add(k, v)
	}

	ipa := policy.NewIPMap(map[string]string{
		"bridge": info.NetworkSettings.IPAddress,
	})

	return policy.NewPURuntime(info.Name, info.State.Pid, tags, ipa), nil
}

// dockerMonitor implements the connection to Docker and monitoring based on events
type dockerMonitor struct {
	dockerClient       *dockerClient.Client
	metadataExtractor  DockerMetadataExtractor
	handlers           map[DockerEvent]func(event *events.Message) error
	eventnotifications chan *events.Message
	stopprocessor      chan bool
	stoplistener       chan bool
	syncAtStart        bool

	collector collector.EventCollector
	puHandler ProcessingUnitsHandler
}

// NewDockerMonitor returns a pointer to a DockerMonitor initialized with the given
// socketType ('tcp' or 'unix') and socketAddress (a port for 'tcp' or
// a socket file for 'unix').
//
// After creating a new DockerMonitor, call addHandler to install one
// or more callback handlers for the events to monitor. Then call Start.
func NewDockerMonitor(
	socketType string,
	socketAddress string,
	p ProcessingUnitsHandler,
	m DockerMetadataExtractor,
	l collector.EventCollector, syncAtStart bool,
) Monitor {

	cli, err := initDockerClient(socketType, socketAddress)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "monitor",
			"error":   err.Error(),
		}).Fatal("Unable to initialize Docker client")
	}

	d := &dockerMonitor{
		puHandler:          p,
		collector:          l,
		syncAtStart:        syncAtStart,
		eventnotifications: make(chan *events.Message, 1000),
		handlers:           make(map[DockerEvent]func(event *events.Message) error),
		stoplistener:       make(chan bool),
		stopprocessor:      make(chan bool),
		metadataExtractor:  m,
		dockerClient:       cli,
	}

	// Add handlers for the events that we know how to process
	d.addHandler(DockerEventCreate, d.handleCreateEvent)
	d.addHandler(DockerEventStart, d.handleStartEvent)
	d.addHandler(DockerEventDie, d.handleDieEvent)
	d.addHandler(DockerEventDestroy, d.handleDestroyEvent)
	d.addHandler(DockerEventPause, d.handlePauseEvent)
	d.addHandler(DockerEventUnpause, d.handleUnpauseEvent)
	d.addHandler(DockerEventConnect, d.handleNetworkConnectEvent)

	return d
}

// addHandler adds a callback handler for the given docker event.
// Interesting event names include 'start' and 'die'. For more on events see
// https://docs.docker.com/engine/reference/api/docker_remote_api/
// under the section 'Docker Events'.
func (d *dockerMonitor) addHandler(event DockerEvent, handler DockerEventHandler) {
	d.handlers[event] = handler
}

// Start will start the DockerPolicy Enforcement.
// It applies a policy to each Container already Up and Running.
// It listens to all ContainerEvents
func (d *dockerMonitor) Start() error {

	log.WithFields(log.Fields{
		"package": "monitor",
	}).Debug("Starting the docker monitor")

	// Starting the eventListener First.
	go d.eventListener()

	//Syncing all Existing containers depending on MonitorSetting
	if d.syncAtStart {
		err := d.syncContainers()

		if err != nil {
			log.WithFields(log.Fields{
				"package": "monitor",
				"error":   err.Error(),
			}).Error("Error Syncing existingContainers")
		}
	}

	// Processing the events received duringthe time of Sync.
	go d.eventProcessor()

	return nil
}

// Stop monitoring docker events.
func (d *dockerMonitor) Stop() error {

	log.WithFields(log.Fields{
		"package": "monitor",
	}).Debug("Stopping the docker monitor")

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
				f, present := d.handlers[DockerEvent(event.Action)]
				if present {
					log.WithFields(log.Fields{
						"package": "monitor",
					}).Debug("Handling docker event")

					err := f(event)

					if err != nil {
						log.WithFields(log.Fields{
							"package": "monitor",
							"error":   err.Error(),
						}).Error("Error while handling event")
					}
				} else {
					log.WithFields(log.Fields{
						"package": "monitor",
					}).Debug("Docker event not handled.")
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
			log.WithFields(log.Fields{
				"package": "monitor",
				"message": message,
			}).Debug("Got message from docker client")
			d.eventnotifications <- &message
		case err := <-errs:
			if err != nil && err != io.EOF {
				log.WithFields(log.Fields{
					"package": "monitor",
					"error":   err.Error(),
				}).Debug("Received docker event error")
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

	log.WithFields(log.Fields{
		"package": "monitor",
	}).Debug("Syncing all existing containers")

	options := types.ContainerListOptions{All: true}
	containers, err := d.dockerClient.ContainerList(context.Background(), options)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "monitor",
			"error":   err.Error(),
		}).Error("Error Getting ContainerList")
		return fmt.Errorf("Error Getting ContainerList: %s", err)
	}

	for _, c := range containers {
		container, err := d.dockerClient.ContainerInspect(context.Background(), c.ID)

		if err != nil {
			log.WithFields(log.Fields{
				"package": "monitor",
				"error":   err.Error(),
			}).Error("Error Syncing existing Container")
		}

		if container.State.Running {
			// Only activate container if it is up and running.

			if err := d.startDockerContainer(&container); err != nil {
				log.WithFields(log.Fields{
					"package": "monitor",
					"error":   err.Error(),
				}).Error("Error Syncing existing Container")
			}

			if container.State.Paused {
				// Notify also that the container  is paused (and running)
				err := <-d.puHandler.HandlePUEvent(contextIDFromDockerID(container.ID), EventPause)
				if err != nil {
					log.WithFields(log.Fields{
						"package": "monitor",
						"error":   err.Error(),
					}).Error("Error handling Container in paused state")
				}
			}
		} else {
			// Container is not running. Simply notify that it's stopped:
			d.stopDockerContainer(container.ID)
		}

	}

	return nil
}

func (d *dockerMonitor) startDockerContainer(dockerInfo *types.ContainerJSON) error {

	log.WithFields(log.Fields{
		"package": "monitor",
	}).Debug("Add/Update a docker container")

	timeout := time.Second * 0

	if !dockerInfo.State.Running {
		log.WithFields(log.Fields{
			"package": "monitor",
		}).Debug("Container is not running - Activation not needed.")

		return nil
	}

	contextID, err := contextIDFromDockerID(dockerInfo.ID)

	if err != nil {
		log.WithFields(log.Fields{
			"package":    "monitor",
			"dockerInfo": dockerInfo,
		}).Debug("Error getting ContextID")

		return fmt.Errorf("Couldn't generate ContextID: %s", err)
	}

	runtimeInfo, err := d.extractMetadata(dockerInfo)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "monitor",
			"contextID": contextID,
		}).Debug("Error getting some of the Docker primitives")

		return fmt.Errorf("Error getting some of the Docker primitives: %s", err)
	}

	ip, ok := runtimeInfo.DefaultIPAddress()

	if !ok || ip == "" {
		log.WithFields(log.Fields{
			"package":   "monitor",
			"contextID": contextID,
		}).Debug("IP Not present in container, Attempting activation")

		ip = ""
	}

	d.puHandler.SetPURuntime(contextID, runtimeInfo)
	errorChan := d.puHandler.HandlePUEvent(contextID, EventStart)

	if err := <-errorChan; err != nil {
		log.WithFields(log.Fields{
			"package":   "monitor",
			"contextID": contextID,
		}).Debug("Setting policy failed. Stopping the container")

		d.dockerClient.ContainerStop(context.Background(), dockerInfo.ID, &timeout)
		d.collector.CollectContainerEvent(contextID, ip, nil, collector.ContainerFailed)
		return fmt.Errorf("Policy cound't be set - container was killed")
	}

	d.collector.CollectContainerEvent(contextID, ip, runtimeInfo.Tags(), collector.ContainerStart)

	return nil
}

func (d *dockerMonitor) stopDockerContainer(dockerID string) error {

	log.WithFields(log.Fields{
		"package":  "monitor",
		"dockerID": dockerID,
	}).Debug("Monitor removed docker container")

	contextID, err := contextIDFromDockerID(dockerID)

	if err != nil {
		log.WithFields(log.Fields{
			"package":  "monitor",
			"dockerID": dockerID,
		}).Debug("Error getting ContextID")

		return fmt.Errorf("Couldn't generate ContextID: %s", err)
	}

	errChan := d.puHandler.HandlePUEvent(contextID, EventStop)
	return <-errChan
}

// ExtractMetadata generates the RuntimeInfo based on Docker primitive
func (d *dockerMonitor) extractMetadata(dockerInfo *types.ContainerJSON) (*policy.PURuntime, error) {

	if dockerInfo == nil {

		log.WithFields(log.Fields{
			"package": "monitor",
		}).Debug("DockerInfo is empty when exacting the metadata")

		return nil, fmt.Errorf("DockerInfo is empty")
	}

	if d.metadataExtractor != nil {
		return d.metadataExtractor(dockerInfo)
	}

	return defaultDockerMetadataExtractor(dockerInfo)
}

// handleCreateEvent generates a create event type.
func (d *dockerMonitor) handleCreateEvent(event *events.Message) error {
	dockerID := event.ID
	contextID, err := contextIDFromDockerID(dockerID)
	if err != nil {
		return fmt.Errorf("Error Generating ContextID: %s", err)
	}

	d.collector.CollectContainerEvent(contextID, "", nil, collector.ContainerCreate)
	// Send the event upstream
	errChan := d.puHandler.HandlePUEvent(contextID, EventCreate)
	return <-errChan
}

// handleStartEvent will notify the agent immediately about the event in order
//to start the implementation of the functions. The agent must query
//the policy engine for details on what to do with this container.
func (d *dockerMonitor) handleStartEvent(event *events.Message) error {

	log.WithFields(log.Fields{
		"package": "monitor",
	}).Debug("Monitor handled start event")

	timeout := time.Second * 0
	dockerID := event.ID
	contextID, err := contextIDFromDockerID(dockerID)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "monitor",
			"error":   err.Error(),
		}).Debug("Error getting ContextID")

		return fmt.Errorf("Error Generating ContextID: %s", err)
	}

	info, err := d.dockerClient.ContainerInspect(context.Background(), dockerID)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "monitor",
			"contextID": contextID,
			"dockerID":  dockerID,
			"error":     err.Error(),
		}).Debug("Error when inspecting the container, kill the container for security reasons")

		//If we see errors, we will kill the container for security reasons.
		d.dockerClient.ContainerStop(context.Background(), dockerID, &timeout)
		d.collector.CollectContainerEvent(contextID, "", nil, collector.ContainerFailed)
		return fmt.Errorf("Cannot read container information. Killing container. ")
	}

	if err := d.startDockerContainer(&info); err != nil {
		log.WithFields(log.Fields{
			"package":   "monitor",
			"contextID": contextID,
			"dockerID":  dockerID,
			"error":     err.Error(),
		}).Debug("Error when adding the container")

		return err
	}

	return nil
}

//handleDie event is called when a container dies. It generates a "Stop" event.
func (d *dockerMonitor) handleDieEvent(event *events.Message) error {

	log.WithFields(log.Fields{
		"package": "monitor",
	}).Debug("Monitor handled die event")

	dockerID := event.ID
	contextID, err := contextIDFromDockerID(dockerID)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "monitor",
			"error":   err.Error(),
		}).Debug("Error getting ContextID")

		return fmt.Errorf("Error Generating ContextID: %s", err)
	}

	d.collector.CollectContainerEvent(contextID, "", nil, collector.ContainerStop)

	return d.stopDockerContainer(dockerID)
}

// handleDestroyEvent handles destroy events from Docker. It generated a "Destroy event"
func (d *dockerMonitor) handleDestroyEvent(event *events.Message) error {

	log.WithFields(log.Fields{
		"package": "monitor",
	}).Debug("Monitor handled destroy event")

	dockerID := event.ID
	contextID, err := contextIDFromDockerID(dockerID)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "monitor",
			"error":   err.Error(),
		}).Debug("Error getting ContextID")

		return fmt.Errorf("Error Generating ContextID: %s", err)
	}

	d.collector.CollectContainerEvent(contextID, "", nil, collector.UnknownContainerDelete)
	// Send the event upstream
	errChan := d.puHandler.HandlePUEvent(contextID, EventDestroy)
	return <-errChan
}

// handleCreateEvent generates a create event type.
func (d *dockerMonitor) handlePauseEvent(event *events.Message) error {
	dockerID := event.ID
	contextID, err := contextIDFromDockerID(dockerID)
	if err != nil {
		return fmt.Errorf("Error Generating ContextID: %s", err)
	}

	errChan := d.puHandler.HandlePUEvent(contextID, EventPause)
	return <-errChan
}

// handleCreateEvent generates a create event type.
func (d *dockerMonitor) handleUnpauseEvent(event *events.Message) error {
	dockerID := event.ID
	contextID, err := contextIDFromDockerID(dockerID)
	if err != nil {
		return fmt.Errorf("Error Generating ContextID: %s", err)
	}

	// Send the event upstream
	errChan := d.puHandler.HandlePUEvent(contextID, EventUnpause)
	return <-errChan
}

func (d *dockerMonitor) handleNetworkConnectEvent(event *events.Message) error {

	log.WithFields(log.Fields{
		"package": "monitor",
	}).Debug("Monitor handled network connect event")

	id := event.Actor.Attributes["container"]

	_, err := d.dockerClient.ContainerInspect(context.Background(), id)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "monitor",
			"error":   err.Error(),
		}).Error("Failed to read the affected container.")
		return err
	}

	return nil
}
