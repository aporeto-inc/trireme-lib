package dockermonitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/dchest/siphash"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"

	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"

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

	// DockerHostMode is the string of the network mode that indicates a host namespace
	DockerHostMode = "host"
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
		return nil, fmt.Errorf("Error creating Docker Client %s", err.Error())
	}

	return dockerClient, nil
}

// defaultDockerMetadataExtractor is the default metadata extractor for Docker
func defaultDockerMetadataExtractor(info *types.ContainerJSON) (*policy.PURuntime, error) {

	tags := policy.NewTagStore()
	tags.AppendKeyValue("@sys:image", info.Config.Image)
	tags.AppendKeyValue("@sys:name", info.Name)

	for k, v := range info.Config.Labels {
		tags.AppendKeyValue("@usr:"+k, v)
	}

	ipa := policy.ExtendedMap{
		"bridge": info.NetworkSettings.IPAddress,
	}

	if info.HostConfig.NetworkMode == DockerHostMode {
		return policy.NewPURuntime(info.Name, info.State.Pid, "", tags, ipa, constants.LinuxProcessPU, hostModeOptions(info)), nil
	}

	return policy.NewPURuntime(info.Name, info.State.Pid, "", tags, ipa, constants.ContainerPU, nil), nil
}

// hostModeOptions creates the default options for a host-mode container. This is done
// based on the policy and the metadata extractor logic and can very by implementation
func hostModeOptions(dockerInfo *types.ContainerJSON) policy.ExtendedMap {

	// Create the options needed to activate
	options := policy.ExtendedMap{
		cgnetcls.PortTag:       "0",
		cgnetcls.CgroupNameTag: strconv.Itoa(dockerInfo.State.Pid),
	}

	ports := ""

	for p := range dockerInfo.Config.ExposedPorts {
		if p.Proto() == "tcp" {
			if ports == "" {
				ports = p.Port()
			} else {
				ports = ports + "," + p.Port()
			}
		}
	}

	if len(ports) > 0 {
		options[cgnetcls.PortTag] = ports
	}

	options[cgnetcls.CgroupMarkTag] = strconv.FormatUint(cgnetcls.MarkVal(), 10)

	return options
}

// dockerMonitor implements the connection to Docker and monitoring based on events
type dockerMonitor struct {
	dockerClient       *dockerClient.Client
	metadataExtractor  DockerMetadataExtractor
	handlers           map[DockerEvent]func(event *events.Message) error
	eventnotifications []chan *events.Message
	stopprocessor      []chan bool
	numberOfQueues     int
	stoplistener       chan bool
	syncHandler        monitor.SynchronizationHandler

	collector collector.EventCollector
	puHandler monitor.ProcessingUnitsHandler

	netcls cgnetcls.Cgroupnetcls
	// killContainerError if enabled kills the container if a policy setting resulted in an error.
	killContainerOnPolicyError bool
	syncAtStart                bool
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
	p monitor.ProcessingUnitsHandler,
	m DockerMetadataExtractor,
	l collector.EventCollector,
	syncAtStart bool,
	s monitor.SynchronizationHandler,
	killContainerOnPolicyError bool,
) monitor.Monitor {

	cli, err := initDockerClient(socketType, socketAddress)

	if err != nil {
		zap.L().Debug("Unable to initialize Docker client", zap.Error(err))
		return nil
	}

	d := &dockerMonitor{
		puHandler:                  p,
		collector:                  l,
		handlers:                   make(map[DockerEvent]func(event *events.Message) error),
		stoplistener:               make(chan bool),
		metadataExtractor:          m,
		dockerClient:               cli,
		syncAtStart:                syncAtStart,
		syncHandler:                s,
		killContainerOnPolicyError: killContainerOnPolicyError,
		netcls: cgnetcls.NewDockerCgroupNetController(),
	}

	d.numberOfQueues = runtime.NumCPU() * 8
	d.eventnotifications = make([]chan *events.Message, d.numberOfQueues)
	d.stopprocessor = make([]chan bool, d.numberOfQueues)

	for i := 0; i < d.numberOfQueues; i++ {
		d.eventnotifications[i] = make(chan *events.Message, 1000)
		d.stopprocessor[i] = make(chan bool)
	}

	// Add handlers for the events that we know how to process
	d.addHandler(DockerEventCreate, d.handleCreateEvent)
	d.addHandler(DockerEventStart, d.handleStartEvent)
	d.addHandler(DockerEventDie, d.handleDieEvent)
	d.addHandler(DockerEventDestroy, d.handleDestroyEvent)
	d.addHandler(DockerEventPause, d.handlePauseEvent)
	d.addHandler(DockerEventUnpause, d.handleUnpauseEvent)

	return d
}

// addHandler adds a callback handler for the given docker event.
// Interesting event names include 'start' and 'die'. For more on events see
// https://docs.docker.com/engine/reference/api/docker_remote_api/
// under the section 'Docker Events'.
func (d *dockerMonitor) addHandler(event DockerEvent, handler DockerEventHandler) {
	d.handlers[event] = handler
}

// sendRequestToQueue sends a request to a channel based on a hash function
func (d *dockerMonitor) sendRequestToQueue(r *events.Message) {

	key0 := uint64(256203161)
	key1 := uint64(982451653)

	h := siphash.Hash(key0, key1, []byte(r.ID))

	d.eventnotifications[int(h%uint64(d.numberOfQueues))] <- r
}

// Start will start the DockerPolicy Enforcement.
// It applies a policy to each Container already Up and Running.
// It listens to all ContainerEvents
func (d *dockerMonitor) Start() error {

	zap.L().Debug("Starting the docker monitor")

	//Check if the server is running before you go ahead
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, pingerr := d.dockerClient.Ping(ctx)
	if pingerr != nil {
		return fmt.Errorf("Docker daemon not running")
	}

	// Starting the eventListener First.
	// We use a channel in order to wait for the eventListener to be ready
	listenerReady := make(chan struct{})
	go d.eventListener(listenerReady)
	<-listenerReady

	//Syncing all Existing containers depending on MonitorSetting
	if d.syncAtStart {
		err := d.syncContainers()

		if err != nil {
			zap.L().Error("Error Syncing existingContainers", zap.Error(err))
		}
	}

	// Processing the events received duringthe time of Sync.
	go d.eventProcessors()

	return nil
}

// Stop monitoring docker events.
func (d *dockerMonitor) Stop() error {

	zap.L().Debug("Stopping the docker monitor")

	d.stoplistener <- true
	for i := 0; i < d.numberOfQueues; i++ {
		d.stopprocessor[i] <- true
	}

	return nil
}

// eventProcessor processes docker events
func (d *dockerMonitor) eventProcessors() {

	for i := 0; i < d.numberOfQueues; i++ {
		go func(i int) {
			for {
				select {
				case event := <-d.eventnotifications[i]:
					if event.Action != "" {
						f, ok := d.handlers[DockerEvent(event.Action)]
						if ok {
							err := f(event)
							if err != nil {
								zap.L().Error("Error while handling event",
									zap.String("action", event.Action),
									zap.Error(err),
								)
							}
						} else {
							zap.L().Debug("Docker event not handled.", zap.String("action", event.Action))
						}
					}
				case <-d.stopprocessor[i]:
					return
				}
			}
		}(i)
	}
}

// eventListener listens to Docker events from the daemon and passes to
// to the processor through a buffered channel. This minimizes the chances
// that we will miss events because the processor is delayed
func (d *dockerMonitor) eventListener(listenerReady chan struct{}) {

	options := types.EventsOptions{}
	options.Filters = filters.NewArgs()
	options.Filters.Add("type", "container")

	messages, errs := d.dockerClient.Events(context.Background(), options)

	// Once the buffered event channel was returned by Docker we return the ready status.
	listenerReady <- struct{}{}

	for {
		select {
		case message := <-messages:
			zap.L().Debug("Got message from docker client", zap.String("action", message.Action))
			d.sendRequestToQueue(&message)

		case err := <-errs:
			if err != nil && err != io.EOF {
				zap.L().Warn("Received docker event error", zap.Error(err))
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

	zap.L().Debug("Syncing all existing containers")

	options := types.ContainerListOptions{All: true}
	containers, err := d.dockerClient.ContainerList(context.Background(), options)

	if err != nil {
		return fmt.Errorf("Error Getting ContainerList: %s", err)
	}

	if d.syncHandler != nil {
		for _, c := range containers {
			container, err := d.dockerClient.ContainerInspect(context.Background(), c.ID)

			if err != nil {
				zap.L().Error("Error Syncing existing Container", zap.Error(err))
				continue
			}

			contextID, _ := contextIDFromDockerID(container.ID)

			PURuntime, _ := d.extractMetadata(&container)

			var state monitor.State
			if container.State.Running {
				if !container.State.Paused {
					state = monitor.StateStarted
				} else {
					state = monitor.StatePaused
				}
			} else {
				state = monitor.StateStopped
			}
			if err := d.syncHandler.HandleSynchronization(contextID, state, PURuntime, monitor.SynchronizationTypeInitial); err != nil {
				zap.L().Error("Error Syncing existing Container", zap.Error(err))
			}
		}

		d.syncHandler.HandleSynchronizationComplete(monitor.SynchronizationTypeInitial)
	}

	for _, c := range containers {
		container, err := d.dockerClient.ContainerInspect(context.Background(), c.ID)

		if err != nil {
			zap.L().Error("Error Syncing existing Container during inspect", zap.Error(err))
			continue
		}

		if err := d.startDockerContainer(&container); err != nil {
			zap.L().Error("Error Syncing existing Container during start handling", zap.Error(err))
			continue
		}

		zap.L().Info("Successfully synced container: ", zap.String("ID", container.ID))

	}

	return nil
}

// setupHostMode sets up the net_cls cgroup for the host mode
func (d *dockerMonitor) setupHostMode(contextID string, runtimeInfo *policy.PURuntime, dockerInfo *types.ContainerJSON) error {

	if err := d.netcls.Creategroup(contextID); err != nil {
		return err
	}

	markval, ok := runtimeInfo.Options().Get(cgnetcls.CgroupMarkTag)
	if !ok {
		if derr := d.netcls.DeleteCgroup(contextID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return errors.New("Mark value not found")
	}

	mark, _ := strconv.ParseUint(markval, 10, 32)
	if err := d.netcls.AssignMark(contextID, mark); err != nil {
		if derr := d.netcls.DeleteCgroup(contextID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return err
	}

	if err := d.netcls.AddProcess(contextID, dockerInfo.State.Pid); err != nil {
		if derr := d.netcls.DeleteCgroup(contextID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return err
	}

	return nil
}

func (d *dockerMonitor) startDockerContainer(dockerInfo *types.ContainerJSON) error {
	timeout := time.Second * 0

	if !dockerInfo.State.Running {
		return nil
	}

	contextID, err := contextIDFromDockerID(dockerInfo.ID)
	if err != nil {
		return fmt.Errorf("Couldn't generate ContextID: %s", err)
	}

	runtimeInfo, err := d.extractMetadata(dockerInfo)
	if err != nil {
		return fmt.Errorf("Error getting some of the Docker primitives: %s", err)
	}

	if err := d.puHandler.SetPURuntime(contextID, runtimeInfo); err != nil {
		return err
	}

	if err := d.puHandler.HandlePUEvent(contextID, monitor.EventStart); err != nil {
		if d.killContainerOnPolicyError {
			if derr := d.dockerClient.ContainerStop(context.Background(), dockerInfo.ID, &timeout); derr != nil {
				zap.L().Warn("Failed to stop bad container", zap.Error(derr))
			}
			return fmt.Errorf("Policy cound't be set - container was killed %s %s", contextID, err)
		}
		return fmt.Errorf("Policy cound't be set - container was kept alive per policy %s %s", contextID, err)
	}

	if dockerInfo.HostConfig.NetworkMode == DockerHostMode {
		if err := d.setupHostMode(contextID, runtimeInfo, dockerInfo); err != nil {
			return fmt.Errorf("Failed to setup host mode ")
		}
	}

	return nil
}

func (d *dockerMonitor) stopDockerContainer(dockerID string) error {

	contextID, err := contextIDFromDockerID(dockerID)

	if err != nil {
		return fmt.Errorf("Couldn't generate ContextID: %s", err)
	}

	return d.puHandler.HandlePUEvent(contextID, monitor.EventStop)
}

// ExtractMetadata generates the RuntimeInfo based on Docker primitive
func (d *dockerMonitor) extractMetadata(dockerInfo *types.ContainerJSON) (*policy.PURuntime, error) {

	if dockerInfo == nil {
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

	return d.puHandler.HandlePUEvent(contextID, monitor.EventCreate)
}

// handleStartEvent will notify the agent immediately about the event in order
//to start the implementation of the functions. The agent must query
//the policy engine for details on what to do with this container.
func (d *dockerMonitor) handleStartEvent(event *events.Message) error {

	timeout := time.Second * 0
	dockerID := event.ID
	contextID, err := contextIDFromDockerID(dockerID)

	if err != nil {
		return fmt.Errorf("Error Generating ContextID: %s", err)
	}

	info, err := d.dockerClient.ContainerInspect(context.Background(), dockerID)

	if err != nil {
		// If we see errors, we will kill the container for security reasons if DockerMonitor was configured to do so.
		if d.killContainerOnPolicyError {
			if err := d.dockerClient.ContainerStop(context.Background(), dockerID, &timeout); err != nil {
				zap.L().Warn("Failed to stop illegal container", zap.Error(err))
			}

			d.collector.CollectContainerEvent(&collector.ContainerRecord{
				ContextID: contextID,
				IPAddress: "N/A",
				Tags:      nil,
				Event:     collector.ContainerFailed,
			})
			return fmt.Errorf("Cannot read container information. Killing container. ")
		}
		return fmt.Errorf("Cannot read container information. Container still alive per policy. ")
	}

	return d.startDockerContainer(&info)
}

//handleDie event is called when a container dies. It generates a "Stop" event.
func (d *dockerMonitor) handleDieEvent(event *events.Message) error {

	return d.stopDockerContainer(event.ID)
}

// handleDestroyEvent handles destroy events from Docker. It generated a "Destroy event"
func (d *dockerMonitor) handleDestroyEvent(event *events.Message) error {

	dockerID := event.ID
	contextID, err := contextIDFromDockerID(dockerID)
	if err != nil {
		return fmt.Errorf("Error Generating ContextID: %s", err)
	}

	err = d.puHandler.HandlePUEvent(contextID, monitor.EventDestroy)

	if err != nil {
		zap.L().Error("Failed to handle delete event",
			zap.Error(err),
		)
	}

	if err := d.netcls.DeleteCgroup(contextID); err != nil {
		zap.L().Warn("Failed to clean netcls group",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	return nil
}

// handlePauseEvent generates a create event type.
func (d *dockerMonitor) handlePauseEvent(event *events.Message) error {
	dockerID := event.ID
	contextID, err := contextIDFromDockerID(dockerID)
	if err != nil {
		return fmt.Errorf("Error Generating ContextID: %s", err)
	}

	return d.puHandler.HandlePUEvent(contextID, monitor.EventPause)
}

// handleCreateEvent generates a create event type.
func (d *dockerMonitor) handleUnpauseEvent(event *events.Message) error {
	dockerID := event.ID
	contextID, err := contextIDFromDockerID(dockerID)
	if err != nil {
		return fmt.Errorf("Error Generating ContextID: %s", err)
	}

	return d.puHandler.HandlePUEvent(contextID, monitor.EventUnpause)
}
