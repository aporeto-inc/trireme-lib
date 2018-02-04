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

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/monitor/constants"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/dchest/siphash"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"

	tevents "github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/monitor/config"
	"github.com/aporeto-inc/trireme-lib/monitor/extractors"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/registerer"
	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls"

	dockerClient "github.com/docker/docker/client"
)

// DockerMonitor implements the connection to Docker and monitoring based on docker events.
type DockerMonitor struct {
	dockerClient               *dockerClient.Client
	socketType                 string
	socketAddress              string
	metadataExtractor          extractors.DockerMetadataExtractor
	handlers                   map[Event]func(ctx context.Context, event *events.Message) error
	eventnotifications         []chan *events.Message
	stopprocessor              []chan bool
	numberOfQueues             int
	stoplistener               chan bool
	config                     *config.ProcessorConfig
	netcls                     cgnetcls.Cgroupnetcls
	killContainerOnPolicyError bool
	syncAtStart                bool
	NoProxyMode                bool
}

// New returns a new docker monitor.
func New() *DockerMonitor {
	return &DockerMonitor{}
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (d *DockerMonitor) SetupConfig(registerer registerer.Registerer, cfg interface{}) (err error) {

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
	d.handlers = make(map[Event]func(ctx context.Context, event *events.Message) error)
	d.stoplistener = make(chan bool)
	d.netcls = cgnetcls.NewDockerCgroupNetController()
	d.numberOfQueues = runtime.NumCPU() * 8
	d.eventnotifications = make([]chan *events.Message, d.numberOfQueues)
	d.stopprocessor = make([]chan bool, d.numberOfQueues)
	d.NoProxyMode = dockerConfig.NoProxyMode
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
func (d *DockerMonitor) SetupHandlers(c *config.ProcessorConfig) {

	d.config = c
}

// Run will start the DockerPolicy Enforcement.
// It applies a policy to each Container already Up and Running.
// It listens to all ContainerEvents
func (d *DockerMonitor) Run(ctx context.Context) error {

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
func (d *DockerMonitor) addHandler(event Event, handler EventHandler) {
	d.handlers[event] = handler
}

// sendRequestToQueue sends a request to a channel based on a hash function
func (d *DockerMonitor) sendRequestToQueue(r *events.Message) {

	key0 := uint64(256203161)
	key1 := uint64(982451653)

	h := siphash.Hash(key0, key1, []byte(r.ID))

	d.eventnotifications[int(h%uint64(d.numberOfQueues))] <- r
}

// eventProcessor processes docker events. We are processing multiple
// queues in parallel so that we can activate containers as fast
// as possible.
func (d *DockerMonitor) eventProcessors(ctx context.Context) {

	for i := 0; i < d.numberOfQueues; i++ {
		go func(i int) {
			for {
				select {
				case event := <-d.eventnotifications[i]:
					if f, ok := d.handlers[Event(event.Action)]; ok {
						if err := f(ctx, event); err != nil {
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
func (d *DockerMonitor) eventListener(ctx context.Context, listenerReady chan struct{}) {

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
func (d *DockerMonitor) ReSync(ctx context.Context) error {

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

	for _, c := range containers {
		// go func(c types.Container) {
		container, err := d.dockerClient.ContainerInspect(ctx, c.ID)
		if err != nil {
			continue
		}

		puID, _ := puIDFromDockerID(container.ID)

		PURuntime, _ := d.extractMetadata(&container)

		event := common.EventStop
		if container.State.Running {
			if !container.State.Paused {
				event = common.EventStart
			} else {
				event = common.EventPause
			}
		}

		if err := d.config.Policy.HandlePUEvent(ctx, puID, event, PURuntime); err != nil {
			zap.L().Error("Unable to sync existing Container",
				zap.String("dockerID", c.ID),
				zap.Error(err),
			)
		}
		// }(c)
	}

	return nil
}

// setupHostMode sets up the net_cls cgroup for the host mode
func (d *DockerMonitor) setupHostMode(puID string, runtimeInfo *policy.PURuntime, dockerInfo *types.ContainerJSON) (err error) {

	if err = d.netcls.Creategroup(puID); err != nil {
		return err
	}

	// Clean the cgroup on exit, if we have failed t activate.
	defer func() {
		if err != nil {
			if derr := d.netcls.DeleteCgroup(puID); derr != nil {
				zap.L().Warn("Failed to clean cgroup",
					zap.String("puID", puID),
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
	if err := d.netcls.AssignMark(puID, mark); err != nil {
		return err
	}

	if err := d.netcls.AddProcess(puID, dockerInfo.State.Pid); err != nil {
		return err
	}

	return nil
}

func (d *DockerMonitor) startDockerContainer(ctx context.Context, dockerInfo *types.ContainerJSON) error {

	if !dockerInfo.State.Running {
		return nil
	}

	puID, err := puIDFromDockerID(dockerInfo.ID)
	if err != nil {
		return err
	}

	runtimeInfo, err := d.extractMetadata(dockerInfo)
	if err != nil {
		return err
	}

	if err = d.config.Policy.HandlePUEvent(ctx, puID, tevents.EventStart, runtimeInfo); err != nil {
		return fmt.Errorf("unable to set policy: container %s kept alive per policy: %s", puID, err)
	}

	if dockerInfo.HostConfig.NetworkMode == constants.DockerHostMode {
		if err = d.setupHostMode(puID, runtimeInfo, dockerInfo); err != nil {
			return fmt.Errorf("unable to setup host mode for container %s: %s", puID, err)
		}
	}

	return nil
}

func (d *DockerMonitor) retrieveDockerInfo(ctx context.Context, event *events.Message) (*types.ContainerJSON, error) {

	info, err := d.dockerClient.ContainerInspect(ctx, event.ID)
	if err != nil {
		// If we see errors, we will kill the container for security reasons if DockerMonitor was configured to do so.
		if d.killContainerOnPolicyError {
			timeout := 0 * time.Second
			if err1 := d.dockerClient.ContainerStop(ctx, event.ID, &timeout); err1 != nil {
				zap.L().Warn("Unable to stop illegal container",
					zap.String("dockerID", event.ID),
					zap.Error(err1),
				)
			}
			d.config.Collector.CollectContainerEvent(&collector.ContainerRecord{
				ContextID: event.ID,
				IPAddress: nil,
				Tags:      nil,
				Event:     collector.ContainerFailed,
			})
			return nil, fmt.Errorf("unable to read container information: container %s killed: %s", event.ID, err)
		}
		return nil, fmt.Errorf("unable to read container information: container %s kept alive per policy: %s", event.ID, err)
	}
	return &info, nil
}

// ExtractMetadata generates the RuntimeInfo based on Docker primitive
func (d *DockerMonitor) extractMetadata(dockerInfo *types.ContainerJSON) (*policy.PURuntime, error) {

	if dockerInfo == nil {
		return nil, errors.New("docker info is empty")
	}

	if d.metadataExtractor != nil {
		return d.metadataExtractor(dockerInfo)
	}

	return extractors.DefaultMetadataExtractor(dockerInfo)
}

// handleCreateEvent generates a create event type. We extract the metadata
// and start the policy resolution at the create event. No need to wait
// for the start event.
func (d *DockerMonitor) handleCreateEvent(ctx context.Context, event *events.Message) error {

	puID, err := puIDFromDockerID(event.ID)
	if err != nil {
		return err
	}

	info, err := d.retrieveDockerInfo(ctx, event)
	if err != nil {
		return err
	}

	runtimeInfo, err := d.extractMetadata(info)
	if err != nil {
		return err
	}

	return d.config.Policy.HandlePUEvent(ctx, puID, tevents.EventCreate, runtimeInfo)
}

// handleStartEvent will notify the policy engine immediately about the event in order
// to start the implementation of the functions. At this point we know the process ID
// that is needed for the remote enforcers.
func (d *DockerMonitor) handleStartEvent(ctx context.Context, event *events.Message) error {

	info, err := d.retrieveDockerInfo(ctx, event)
	if err != nil {
		return err
	}

	if !info.State.Running {
		return nil
	}

	puID, err := puIDFromDockerID(info.ID)
	if err != nil {
		return err
	}

	pidInfo := policy.NewPURuntime(info.Name, info.State.Pid, "", nil, nil, common.ContainerPU, nil)

	if err = d.config.Policy.HandlePUEvent(ctx, puID, tevents.EventStart, pidInfo); err != nil {
		return fmt.Errorf("unable to set policy: container %s kept alive per policy: %s", puID, err)
	}

	if info.HostConfig.NetworkMode == constants.DockerHostMode {
		if err = d.setupHostMode(puID, pidInfo, info); err != nil {
			return fmt.Errorf("unable to setup host mode for container %s: %s", puID, err)
		}
	}
	return nil
}

//handleDie event is called when a container dies. It generates a "Stop" event.
func (d *DockerMonitor) handleDieEvent(ctx context.Context, event *events.Message) error {

	puID, err := puIDFromDockerID(event.ID)
	if err != nil {
		return err
	}

	return d.config.Policy.HandlePUEvent(ctx, puID, tevents.EventStop, policy.NewPURuntimeWithDefaults())
}

// handleDestroyEvent handles destroy events from Docker. It generated a "Destroy event"
func (d *DockerMonitor) handleDestroyEvent(ctx context.Context, event *events.Message) error {

	puID, err := puIDFromDockerID(event.ID)
	if err != nil {
		return err
	}

	err = d.config.Policy.HandlePUEvent(ctx, puID, tevents.EventDestroy, policy.NewPURuntimeWithDefaults())
	if err != nil {
		zap.L().Error("Failed to handle delete event",
			zap.Error(err),
		)
	}

	if err := d.netcls.DeleteCgroup(puID); err != nil {
		zap.L().Warn("Failed to clean netcls group",
			zap.String("puID", puID),
			zap.Error(err),
		)
	}

	return nil
}

// handlePauseEvent generates a create event type.
func (d *DockerMonitor) handlePauseEvent(ctx context.Context, event *events.Message) error {
	zap.L().Info("UnPause Event for nativeID", zap.String("ID", event.ID))

	puID, err := puIDFromDockerID(event.ID)
	if err != nil {
		return err
	}

	return d.config.Policy.HandlePUEvent(ctx, puID, tevents.EventPause, policy.NewPURuntimeWithDefaults())
}

// handleCreateEvent generates a create event type.
func (d *DockerMonitor) handleUnpauseEvent(ctx context.Context, event *events.Message) error {

	puID, err := puIDFromDockerID(event.ID)
	if err != nil {
		return err
	}

	return d.config.Policy.HandlePUEvent(ctx, puID, tevents.EventUnpause, policy.NewPURuntimeWithDefaults())
}

func puIDFromDockerID(dockerID string) (string, error) {

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

func (d *DockerMonitor) setupDockerDaemon() (err error) {

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
func (d *DockerMonitor) waitForDockerDaemon(ctx context.Context) (err error) {

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
