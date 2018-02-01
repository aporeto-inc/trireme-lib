package dockermonitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/aporeto-inc/trireme-lib/utils/contextstore"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/monitor/constants"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/dchest/siphash"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"

	tevents "github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/monitor/config"
	"github.com/aporeto-inc/trireme-lib/monitor/extractors"
	"github.com/aporeto-inc/trireme-lib/monitor/instance"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/registerer"
	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls"

	dockerClient "github.com/docker/docker/client"
)

// dockerMonitor implements the connection to Docker and monitoring based on docker events.
type dockerMonitor struct {
	dockerClient       *dockerClient.Client
	socketType         string
	socketAddress      string
	metadataExtractor  extractors.DockerMetadataExtractor
	handlers           map[Event]func(event *events.Message) error
	eventnotifications []chan *events.Message
	stopprocessor      []chan bool
	numberOfQueues     int
	stoplistener       chan bool
	config             *config.ProcessorConfig
	netcls             cgnetcls.Cgroupnetcls
	// killContainerError if enabled kills the container if a policy setting resulted in an error.
	killContainerOnPolicyError bool
	syncAtStart                bool
	NoProxyMode                bool
	cstore                     contextstore.ContextStore
}

// New returns a new docker monitor.
func New() monitorinstance.Implementation {
	return &dockerMonitor{}
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (d *dockerMonitor) SetupConfig(registerer registerer.Registerer, cfg interface{}) (err error) {

	defaultConfig := DefaultConfig()

	if cfg == nil {
		cfg = defaultConfig
	}

	dockerConfig, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified")
	}

	// Setup defaults
	dockerConfig = SetupDefaultConfig(dockerConfig)

	d.socketType = dockerConfig.SocketType
	d.socketAddress = dockerConfig.SocketAddress
	d.metadataExtractor = dockerConfig.EventMetadataExtractor
	d.syncAtStart = dockerConfig.SyncAtStart
	d.killContainerOnPolicyError = dockerConfig.KillContainerOnPolicyError
	d.handlers = make(map[Event]func(event *events.Message) error)
	d.stoplistener = make(chan bool)
	d.netcls = cgnetcls.NewDockerCgroupNetController()
	d.numberOfQueues = runtime.NumCPU() * 8
	d.eventnotifications = make([]chan *events.Message, d.numberOfQueues)
	d.stopprocessor = make([]chan bool, d.numberOfQueues)
	d.NoProxyMode = dockerConfig.NoProxyMode
	d.cstore = contextstore.NewFileContextStore(cstorePath, nil)
	for i := 0; i < d.numberOfQueues; i++ {
		d.eventnotifications[i] = make(chan *events.Message, 1000)
		d.stopprocessor[i] = make(chan bool)
	}

	// Add handlers for the events that we know how to process
	d.addHandler(EventCreate, d.handleCreateEvent)
	d.addHandler(EventStart, d.handleStartEvent)
	d.addHandler(EventDie, d.handleDieEvent)
	d.addHandler(EventDestroy, d.handleDestroyEvent)
	d.addHandler(EventPause, d.handlePauseEvent)
	d.addHandler(EventUnpause, d.handleUnpauseEvent)

	return nil
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (d *dockerMonitor) SetupHandlers(c *config.ProcessorConfig) {

	d.config = c
}

// Start will start the DockerPolicy Enforcement.
// It applies a policy to each Container already Up and Running.
// It listens to all ContainerEvents
func (d *dockerMonitor) Run(ctx context.Context) error {

	if err := d.config.IsComplete(); err != nil {
		return fmt.Errorf("docker: %s", err)
	}

	// Processing the events received during the time of Sync.
	go d.eventProcessors(ctx)

	err := d.waitForDockerDaemon(ctx)
	if err == nil {
		zap.L().Debug("Docker daemon setup")
		// Syncing all Existing containers depending on MonitorSetting
		if err := d.ReSync(ctx); err != nil {
			zap.L().Error("Unable to sync existing containers", zap.Error(err))
		}
	} else {
		zap.L().Info("Docker resync skipped")
	}

	return nil
}

// addHandler adds a callback handler for the given docker event.
// Interesting event names include 'start' and 'die'. For more on events see
// https://docs.docker.com/engine/reference/api/docker_remote_api/
// under the section 'Docker Events'.
func (d *dockerMonitor) addHandler(event Event, handler EventHandler) {
	d.handlers[event] = handler
}

// sendRequestToQueue sends a request to a channel based on a hash function
func (d *dockerMonitor) sendRequestToQueue(r *events.Message) {

	key0 := uint64(256203161)
	key1 := uint64(982451653)

	h := siphash.Hash(key0, key1, []byte(r.ID))

	d.eventnotifications[int(h%uint64(d.numberOfQueues))] <- r
}

// eventProcessor processes docker events. We are processing multiple
// queues in parallel so that we can activate containers as fast
// as possible.
func (d *dockerMonitor) eventProcessors(ctx context.Context) {

	for i := 0; i < d.numberOfQueues; i++ {
		go func(i int) {
			for {
				select {
				case event := <-d.eventnotifications[i]:
					if f, ok := d.handlers[Event(event.Action)]; ok {
						if err := f(event); err != nil {
							zap.L().Error("Unable to handle docker event",
								zap.String("action", event.Action),
								zap.Error(err),
							)
						}
						continue
					}
				case <-ctx.Done():
					return
				}
			}
		}(i)
	}
}

// eventListener listens to Docker events from the daemon and passes to
// to the processor through a buffered channel. This minimizes the chances
// that we will miss events because the processor is delayed
func (d *dockerMonitor) eventListener(ctx context.Context, listenerReady chan struct{}) {

	f := filters.NewArgs()
	f.Add("type", "container")
	options := types.EventsOptions{
		Filters: f,
	}

	messages, errs := d.dockerClient.Events(context.Background(), options)

	// Once the buffered event channel was returned by Docker we return the ready status.
	listenerReady <- struct{}{}

	for {
		select {
		case message := <-messages:
			zap.L().Debug("Got message from docker client",
				zap.String("action", message.Action),
				zap.String("ID", message.ID),
			)
			d.sendRequestToQueue(&message)

		case err := <-errs:
			if err != nil && err != io.EOF {
				zap.L().Warn("Received docker event error",
					zap.Error(err),
				)
			}
		case <-ctx.Done():
			return
		}
	}
}

// ReSync resyncs all the existing containers on the Host, using the
// same process as when a container is initially spawn up
func (d *dockerMonitor) ReSync(ctx context.Context) error {

	if !d.syncAtStart || d.config.Policy == nil {
		zap.L().Debug("No synchronization of containers performed")
		return nil
	}

	zap.L().Debug("Syncing all existing containers")

	options := types.ContainerListOptions{All: true}
	containers, err := d.dockerClient.ContainerList(ctx, options)
	if err != nil {
		return fmt.Errorf("unable to get container list: %s", err)
	}

	allContainers := map[string]types.ContainerJSON{}

	for _, c := range containers {
		container, err := d.dockerClient.ContainerInspect(ctx, c.ID)
		if err != nil {
			zap.L().Error("unable to sync existing container",
				zap.String("dockerID", c.ID),
				zap.Error(err),
			)
			continue
		}

		contextID, _ := contextIDFromDockerID(container.ID)

		storedContext := &StoredContext{}
		if d.NoProxyMode {
			if err = d.cstore.Retrieve(contextID, &storedContext); err == nil {
				container.Config.Labels["storedTags"] = strings.Join(storedContext.Tags.GetSlice(), ",")
			}
		}

		PURuntime, _ := d.extractMetadata(&container)
		var state tevents.State
		if container.State.Running {
			if !container.State.Paused {
				state = tevents.StateStarted
			} else {
				state = tevents.StatePaused
			}
		} else {
			state = tevents.StateStopped
		}

		if d.NoProxyMode {
			t := PURuntime.Tags()
			if t != nil && storedContext.Tags != nil {
				t.Merge(storedContext.Tags)
				PURuntime.SetTags(t)
			}

		}

		if err := d.config.Policy.HandleSynchronization(
			contextID,
			state,
			PURuntime,
			policy.SynchronizationTypeInitial,
		); err != nil {
			zap.L().Error("Unable to sync existing Container",
				zap.String("dockerID", c.ID),
				zap.Error(err),
			)
		}

		allContainers[contextID] = container
	}

	for _, container := range allContainers {
		if err := d.startDockerContainer(&container); err != nil {
			zap.L().Error("Unable to sync existing container during start handling",
				zap.String("dockerID", container.ID),
				zap.Error(err),
			)
			continue
		}

		zap.L().Debug("Successfully synced container", zap.String("dockerID", container.ID))
	}

	return nil
}

// setupHostMode sets up the net_cls cgroup for the host mode
func (d *dockerMonitor) setupHostMode(contextID string, runtimeInfo *policy.PURuntime, dockerInfo *types.ContainerJSON) (err error) {

	if err = d.netcls.Creategroup(contextID); err != nil {
		return err
	}

	// Clean the cgroup on exit, if we have failed t activate.
	defer func() {
		if err != nil {
			if derr := d.netcls.DeleteCgroup(contextID); derr != nil {
				zap.L().Warn("Failed to clean cgroup",
					zap.String("contextID", contextID),
					zap.Error(derr),
					zap.Error(err),
				)
			}
		}
	}()

	markval := runtimeInfo.Options().CgroupMark
	if markval == "" {
		return errors.New("mark value not found")
	}

	mark, _ := strconv.ParseUint(markval, 10, 32)
	if err := d.netcls.AssignMark(contextID, mark); err != nil {
		return err
	}

	if err := d.netcls.AddProcess(contextID, dockerInfo.State.Pid); err != nil {
		return err
	}

	return nil
}

func (d *dockerMonitor) startDockerContainer(dockerInfo *types.ContainerJSON) error {

	if !dockerInfo.State.Running {
		return nil
	}

	contextID, err := contextIDFromDockerID(dockerInfo.ID)
	if err != nil {
		return err
	}

	storedContext := &StoredContext{}
	if err = d.cstore.Retrieve(contextID, &storedContext); err == nil {
		if storedContext.Tags != nil {
			dockerInfo.Config.Labels["storedTags"] = strings.Join(storedContext.Tags.GetSlice(), ",")
		}
	}

	runtimeInfo, err := d.extractMetadata(dockerInfo)
	if err != nil {
		return err
	}

	t := runtimeInfo.Tags()
	if t != nil && storedContext.Tags != nil {
		t.Merge(storedContext.Tags)
		runtimeInfo.SetTags(t)
	}

	var event tevents.Event
	switch dockerInfo.State.Status {
	case "paused":
		event = tevents.EventPause
	case "running":
		event = tevents.EventStart
	case "dead":
		event = tevents.EventStop
	default:
		//We are restarting.Feeding start here. might as well be stop since we will get start notification when the
		//container finishes restarting
		event = tevents.EventStart
	}

	if err = d.config.Policy.HandlePUEvent(contextID, event, runtimeInfo); err != nil {
		if d.killContainerOnPolicyError {
			if derr := d.dockerClient.ContainerRemove(context.Background(), dockerInfo.ID, types.ContainerRemoveOptions{Force: true}); derr != nil {
				return fmt.Errorf("unable to set policy: unable to remove container %s: %s, %s", contextID, err, derr)
			}
			return fmt.Errorf("unable to set policy: removed container %s: %s", contextID, err)
		}
		return fmt.Errorf("unable to set policy: container %s kept alive per policy: %s", contextID, err)
	}

	if dockerInfo.HostConfig.NetworkMode == constants.DockerHostMode {
		if err = d.setupHostMode(contextID, runtimeInfo, dockerInfo); err != nil {
			return fmt.Errorf("unable to setup host mode for container %s: %s", contextID, err)
		}
	}

	storedContext = &StoredContext{
		containerInfo: dockerInfo,
		Tags:          runtimeInfo.Tags(),
	}

	return d.cstore.Store(contextID, storedContext)
}

func (d *dockerMonitor) stopDockerContainer(dockerID string) error {

	contextID, err := contextIDFromDockerID(dockerID)
	if err != nil {
		return err
	}

	if err = d.cstore.Remove(contextID); err != nil {
		return err
	}

	return d.config.Policy.HandlePUEvent(contextID, tevents.EventStop, nil)
}

// ExtractMetadata generates the RuntimeInfo based on Docker primitive
func (d *dockerMonitor) extractMetadata(dockerInfo *types.ContainerJSON) (*policy.PURuntime, error) {

	if dockerInfo == nil {
		return nil, errors.New("docker info is empty")
	}

	if d.metadataExtractor != nil {
		return d.metadataExtractor(dockerInfo)
	}

	return extractors.DefaultMetadataExtractor(dockerInfo)
}

// handleCreateEvent generates a create event type.
func (d *dockerMonitor) handleCreateEvent(event *events.Message) error {

	contextID, err := contextIDFromDockerID(event.ID)
	if err != nil {
		return err
	}

	return d.config.Policy.HandlePUEvent(contextID, tevents.EventCreate, nil)
}

// handleStartEvent will notify the agent immediately about the event in order
//to start the implementation of the functions. The agent must query
//the policy engine for details on what to do with this container.
func (d *dockerMonitor) handleStartEvent(event *events.Message) error {

	timeout := time.Second * 0

	contextID, err := contextIDFromDockerID(event.ID)
	if err != nil {
		return err
	}

	info, err := d.dockerClient.ContainerInspect(context.Background(), event.ID)
	if err != nil {
		// If we see errors, we will kill the container for security reasons if DockerMonitor was configured to do so.
		if d.killContainerOnPolicyError {

			if err1 := d.dockerClient.ContainerStop(context.Background(), event.ID, &timeout); err1 != nil {
				zap.L().Warn("Unable to stop illegal container",
					zap.String("dockerID", contextID),
					zap.Error(err1),
				)
			}

			d.config.Collector.CollectContainerEvent(&collector.ContainerRecord{
				ContextID: contextID,
				IPAddress: nil,
				Tags:      nil,
				Event:     collector.ContainerFailed,
			})

			return fmt.Errorf("unable to read container information: container %s killed: %s", contextID, err)
		}

		return fmt.Errorf("unable to read container information: container %s kept alive per policy: %s", contextID, err)
	}

	return d.startDockerContainer(&info)
}

//handleDie event is called when a container dies. It generates a "Stop" event.
func (d *dockerMonitor) handleDieEvent(event *events.Message) error {

	return d.stopDockerContainer(event.ID)
}

// handleDestroyEvent handles destroy events from Docker. It generated a "Destroy event"
func (d *dockerMonitor) handleDestroyEvent(event *events.Message) error {

	contextID, err := contextIDFromDockerID(event.ID)
	if err != nil {
		return err
	}

	err = d.config.Policy.HandlePUEvent(contextID, tevents.EventDestroy, nil)
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
	zap.L().Info("UnPause Event for nativeID", zap.String("ID", event.ID))

	contextID, err := contextIDFromDockerID(event.ID)
	if err != nil {
		return err
	}

	return d.config.Policy.HandlePUEvent(contextID, tevents.EventPause, nil)
}

// handleCreateEvent generates a create event type.
func (d *dockerMonitor) handleUnpauseEvent(event *events.Message) error {

	contextID, err := contextIDFromDockerID(event.ID)
	if err != nil {
		return err
	}

	return d.config.Policy.HandlePUEvent(contextID, tevents.EventUnpause, nil)
}

func contextIDFromDockerID(dockerID string) (string, error) {

	if dockerID == "" {
		return "", errors.New("unable to generate context id: empty docker id")
	}

	if len(dockerID) < 12 {
		return "", fmt.Errorf("unable to generate context id: dockerid smaller than 12 characters: %s", dockerID)
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
		return nil, fmt.Errorf("bad socket type: %s", socketType)
	}

	defaultHeaders := map[string]string{"User-Agent": "engine-api-dockerClient-1.0"}

	dockerClient, err := dockerClient.NewClient(socket, DockerClientVersion, nil, defaultHeaders)
	if err != nil {
		return nil, fmt.Errorf("unable to create docker client: %s", err)
	}

	return dockerClient, nil
}

func (d *dockerMonitor) setupDockerDaemon() (err error) {

	if d.dockerClient == nil {
		// Initialize client
		if d.dockerClient, err = initDockerClient(d.socketType, d.socketAddress); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), dockerPingTimeout)
	defer cancel()

	_, err = d.dockerClient.Ping(ctx)
	return err
}

// waitForDockerDaemon is a blocking call which will try to bring up docker, if not return err
// with timeout
func (d *dockerMonitor) waitForDockerDaemon(ctx context.Context) (err error) {

	done := make(chan bool)
	go func() {
		for errg := d.setupDockerDaemon(); errg != nil; {
			zap.L().Debug("Unable to init docker client. Retrying...", zap.Error(errg))
			<-time.After(dockerRetryTimer)
			continue
		}
		done <- true
	}()

	select {
	case <-ctx.Done():
		return nil
	case <-time.After(dockerInitializationWait):
		return fmt.Errorf("Unable to connecto to docker daemon")
	case <-done:
	}

	// Starting the eventListener and wait to hear on channel for it to be ready.
	listenerReady := make(chan struct{})
	go d.eventListener(ctx, listenerReady)
	<-listenerReady

	return err
}
