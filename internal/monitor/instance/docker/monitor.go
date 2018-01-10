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
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/dchest/siphash"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"

	"github.com/aporeto-inc/trireme-lib/internal/monitor/instance"
	"github.com/aporeto-inc/trireme-lib/internal/monitor/rpc/registerer"
	tevents "github.com/aporeto-inc/trireme-lib/rpc/events"
	"github.com/aporeto-inc/trireme-lib/rpc/processor"
	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls"
	"github.com/aporeto-inc/trireme-lib/utils/portspec"

	dockerClient "github.com/docker/docker/client"
)

// Event is the type of various docker events.
type Event string

const (
	// EventCreate represents the Docker "create" event.
	EventCreate Event = "create"

	// EventStart represents the Docker "start" event.
	EventStart Event = "start"

	// EventDie represents the Docker "die" event.
	EventDie Event = "die"

	// EventDestroy represents the Docker "destroy" event.
	EventDestroy Event = "destroy"

	// EventPause represents the Docker "pause" event.
	EventPause Event = "pause"

	// EventUnpause represents the Docker "unpause" event.
	EventUnpause Event = "unpause"

	// EventConnect represents the Docker "connect" event.
	EventConnect Event = "connect"

	// DockerClientVersion is the version sent out as the client
	DockerClientVersion = "v1.23"

	// dockerPingTimeout is the time to wait for a ping to succeed.
	dockerPingTimeout = 2 * time.Second

	// dockerRetryTimer is the time after which we will retry to bring docker up.
	dockerRetryTimer = 10 * time.Second

	// dockerInitializationWait is the time after which we will retry to bring docker up.
	dockerInitializationWait = 2 * dockerRetryTimer
)
const (
	cstorePath = "/var/run/trireme/docker"
)

//StoredContext is the format of the data stored in the contextstore
type StoredContext struct {
	containerInfo *types.ContainerJSON
	Tags          *policy.TagStore
}

// A EventHandler is type of docker event handler functions.
type EventHandler func(event *events.Message) error

// A MetadataExtractor is a function used to extract a *policy.PURuntime from a given
// docker ContainerJSON.
type MetadataExtractor func(*types.ContainerJSON) (*policy.PURuntime, error)

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

// defaultMetadataExtractor is the default metadata extractor for Docker
func defaultMetadataExtractor(info *types.ContainerJSON) (*policy.PURuntime, error) {

	tags := policy.NewTagStore()
	tags.AppendKeyValue("@sys:image", info.Config.Image)
	tags.AppendKeyValue("@sys:name", info.Name)

	for k, v := range info.Config.Labels {
		tags.AppendKeyValue("@usr:"+k, v)
	}

	ipa := policy.ExtendedMap{
		"bridge": info.NetworkSettings.IPAddress,
	}

	if info.HostConfig.NetworkMode == constants.DockerHostMode {
		return policy.NewPURuntime(info.Name, info.State.Pid, "", tags, ipa, constants.LinuxProcessPU, hostModeOptions(info)), nil
	}

	return policy.NewPURuntime(info.Name, info.State.Pid, "", tags, ipa, constants.ContainerPU, nil), nil
}

// hostModeOptions creates the default options for a host-mode container. This is done
// based on the policy and the metadata extractor logic and can very by implementation
func hostModeOptions(dockerInfo *types.ContainerJSON) *policy.OptionsType {

	options := policy.OptionsType{
		CgroupName: strconv.Itoa(dockerInfo.State.Pid),
		CgroupMark: strconv.FormatUint(cgnetcls.MarkVal(), 10),
	}

	for p := range dockerInfo.Config.ExposedPorts {
		if p.Proto() == "tcp" {
			s, err := portspec.NewPortSpecFromString(p.Port(), nil)
			if err != nil {
				continue
			}

			options.Services = append(options.Services, policy.Service{
				Protocol: uint8(6),
				Ports:    s,
			})
		}
	}

	return &options
}

// Config is the configuration options to start a CNI monitor
type Config struct {
	EventMetadataExtractor     MetadataExtractor
	SocketType                 string
	SocketAddress              string
	SyncAtStart                bool
	KillContainerOnPolicyError bool
	NoProxyMode                bool
}

// DefaultConfig provides a default configuration
func DefaultConfig() *Config {
	return &Config{
		EventMetadataExtractor:     defaultMetadataExtractor,
		SocketType:                 string(constants.DefaultDockerSocketType),
		SocketAddress:              constants.DefaultDockerSocket,
		SyncAtStart:                true,
		KillContainerOnPolicyError: false,
		NoProxyMode:                false,
	}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(dockerConfig *Config) *Config {

	defaultConfig := DefaultConfig()

	if dockerConfig.EventMetadataExtractor == nil {
		dockerConfig.EventMetadataExtractor = defaultConfig.EventMetadataExtractor
	}
	if dockerConfig.SocketType == "" {
		dockerConfig.SocketType = defaultConfig.SocketType
	}
	if dockerConfig.SocketAddress == "" {
		dockerConfig.SocketAddress = defaultConfig.SocketAddress
	}
	return dockerConfig
}

// dockerMonitor implements the connection to Docker and monitoring based on events
type dockerMonitor struct {
	dockerClient       *dockerClient.Client
	socketType         string
	socketAddress      string
	metadataExtractor  MetadataExtractor
	handlers           map[Event]func(event *events.Message) error
	eventnotifications []chan *events.Message
	stopprocessor      []chan bool
	numberOfQueues     int
	stoplistener       chan bool
	config             *processor.Config
	netcls             cgnetcls.Cgroupnetcls
	// killContainerError if enabled kills the container if a policy setting resulted in an error.
	killContainerOnPolicyError bool
	syncAtStart                bool
	NoProxyMode                bool
	cstore                     contextstore.ContextStore
}

// New returns a new docker monitor
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
	d.cstore = contextstore.NewFileContextStore(cstorePath)
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
func (d *dockerMonitor) SetupHandlers(c *processor.Config) {

	d.config = c
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
		err = ctx.Err()
	case <-done:
	}

	if err == nil {
		// Starting the eventListener and wait to hear on channel for it to be ready.
		listenerReady := make(chan struct{})
		go d.eventListener(listenerReady)
		<-listenerReady
	}

	return err
}

// Start will start the DockerPolicy Enforcement.
// It applies a policy to each Container already Up and Running.
// It listens to all ContainerEvents
func (d *dockerMonitor) Start() error {

	if err := d.config.IsComplete(); err != nil {
		return fmt.Errorf("docker: %s", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dockerInitializationWait)
	defer cancel()

	// Processing the events received during the time of Sync.
	go d.eventProcessors()

	err := d.waitForDockerDaemon(ctx)

	if err == nil {
		zap.L().Debug("Docker daemon setup")
		// Syncing all Existing containers depending on MonitorSetting
		if err := d.ReSync(); err != nil {
			zap.L().Error("Unable to sync existing containers", zap.Error(err))
		}
	} else {
		zap.L().Info("Docker resync skipped")
	}

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
						f, ok := d.handlers[Event(event.Action)]
						if ok {
							err := f(event)
							if err != nil {
								zap.L().Error("Unable to handle docker event",
									zap.String("action", event.Action),
									zap.Error(err),
								)
							}
						} else {
							zap.L().Debug("Docker event not handled",
								zap.String("action", event.Action),
								zap.String("ID", event.ID),
							)
						}
					} else {
						zap.L().Info("Empty event",
							zap.String("ID", event.ID),
						)
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
		case stop := <-d.stoplistener:
			if stop {
				return
			}
		}
	}
}

// ReSync resyncs all the existing containers on the Host, using the
// same process as when a container is initially spawn up
func (d *dockerMonitor) ReSync() error {

	if !d.syncAtStart {
		zap.L().Debug("No synchronization of containers performed")
		return nil
	}

	zap.L().Debug("Syncing all existing containers")

	options := types.ContainerListOptions{All: true}
	containers, err := d.dockerClient.ContainerList(context.Background(), options)

	if err != nil {
		return fmt.Errorf("unable to get container list: %s", err)
	}

	if d.config.SyncHandler != nil {

		for _, c := range containers {

			container, err := d.dockerClient.ContainerInspect(context.Background(), c.ID)
			if err != nil {
				zap.L().Error("unable to sync existing container",
					zap.String("dockerID", c.ID),
					zap.Error(err),
				)
				continue
			}

			contextID, _ := contextIDFromDockerID(container.ID)

			if d.NoProxyMode {
				storedContext := &StoredContext{}
				if err = d.cstore.Retrieve(contextID, &storedContext); err == nil {
					container.Config.Labels["storedTags"] = strings.Join(storedContext.Tags.GetSlice(), ",")
				} else {
					if err = d.startDockerContainer(&container); err != nil {
						zap.L().Debug("Could Not restart docker container", zap.String("ID", container.ID), zap.Error(err))
					}
					continue
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
			if d.config.SyncHandler != nil {
				if d.NoProxyMode {
					storedContext := &StoredContext{}
					if err = d.cstore.Retrieve(contextID, &storedContext); err != nil {
						//We don't know about this container lets not sync
						continue
					}

					t := PURuntime.Tags()
					if t != nil && storedContext.Tags != nil {
						t.Merge(storedContext.Tags)
						PURuntime.SetTags(t)
					}

				}
				if err := d.config.SyncHandler.HandleSynchronization(
					contextID,
					state,
					PURuntime,
					processor.SynchronizationTypeInitial,
				); err != nil {
					zap.L().Error("Unable to sync existing Container",
						zap.String("dockerID", c.ID),
						zap.Error(err),
					)
				}
			}
		}
	}

	for _, c := range containers {

		container, err := d.dockerClient.ContainerInspect(context.Background(), c.ID)
		if err != nil {
			zap.L().Error("Unable to sync existing container during inspect",
				zap.String("dockerID", c.ID),
				zap.Error(err),
			)
			continue
		}
		contextID, _ := contextIDFromDockerID(container.ID)
		if d.NoProxyMode {
			storedContext := &StoredContext{}
			if err = d.cstore.Retrieve(contextID, &storedContext); err == nil {
				container.Config.Labels["storedTags"] = strings.Join(storedContext.Tags.GetSlice(), ",")
			}
		}

		if err := d.startDockerContainer(&container); err != nil {
			zap.L().Error("Unable to sync existing container during start handling",
				zap.String("dockerID", c.ID),
				zap.Error(err),
			)
			continue
		}

		zap.L().Debug("Successfully synced container", zap.String("dockerID", container.ID))

	}

	return nil
}

// setupHostMode sets up the net_cls cgroup for the host mode
func (d *dockerMonitor) setupHostMode(contextID string, runtimeInfo *policy.PURuntime, dockerInfo *types.ContainerJSON) error {

	if err := d.netcls.Creategroup(contextID); err != nil {
		return err
	}

	markval := runtimeInfo.Options().CgroupMark
	if markval == "" {
		if derr := d.netcls.DeleteCgroup(contextID); derr != nil {
			zap.L().Warn("Failed to clean cgroup",
				zap.String("contextID", contextID),
				zap.Error(derr),
			)
		}

		return errors.New("mark value not found")
	}

	mark, _ := strconv.ParseUint(markval, 10, 32)
	if err := d.netcls.AssignMark(contextID, mark); err != nil {
		if derr := d.netcls.DeleteCgroup(contextID); derr != nil {
			zap.L().Warn("Failed to clean cgroup",
				zap.String("contextID", contextID),
				zap.Error(derr),
			)
		}

		return err
	}

	if err := d.netcls.AddProcess(contextID, dockerInfo.State.Pid); err != nil {
		if derr := d.netcls.DeleteCgroup(contextID); derr != nil {
			zap.L().Warn("Failed to clean cgroup",
				zap.String("contextID", contextID),
				zap.Error(derr),
			)
		}

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
	if d.cstore != nil {
		if err = d.cstore.Retrieve(contextID, &storedContext); err == nil {
			if storedContext.Tags != nil {
				dockerInfo.Config.Labels["storedTags"] = strings.Join(storedContext.Tags.GetSlice(), ",")
			}

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
	if err = d.config.PUHandler.CreatePURuntime(contextID, runtimeInfo); err != nil {
		return err
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

	if err = d.config.PUHandler.HandlePUEvent(contextID, event); err != nil {
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
	return d.config.PUHandler.HandlePUEvent(contextID, tevents.EventStop)
}

// ExtractMetadata generates the RuntimeInfo based on Docker primitive
func (d *dockerMonitor) extractMetadata(dockerInfo *types.ContainerJSON) (*policy.PURuntime, error) {

	if dockerInfo == nil {
		return nil, errors.New("docker info is empty")
	}

	if d.metadataExtractor != nil {
		return d.metadataExtractor(dockerInfo)
	}

	return defaultMetadataExtractor(dockerInfo)
}

// handleCreateEvent generates a create event type.
func (d *dockerMonitor) handleCreateEvent(event *events.Message) error {

	contextID, err := contextIDFromDockerID(event.ID)
	if err != nil {
		return err
	}

	return d.config.PUHandler.HandlePUEvent(contextID, tevents.EventCreate)
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
				IPAddress: "N/A",
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

	err = d.config.PUHandler.HandlePUEvent(contextID, tevents.EventDestroy)

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

	return d.config.PUHandler.HandlePUEvent(contextID, tevents.EventPause)
}

// handleCreateEvent generates a create event type.
func (d *dockerMonitor) handleUnpauseEvent(event *events.Message) error {

	contextID, err := contextIDFromDockerID(event.ID)
	if err != nil {
		return err
	}

	return d.config.PUHandler.HandlePUEvent(contextID, tevents.EventUnpause)
}
