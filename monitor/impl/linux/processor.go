package linuxmonitor

import (
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/cgnetcls"
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/internal/contextstore"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/monitor/impl"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/eventinfo"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/eventserver"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// Config is the configuration options to start a CNI monitor
type Config struct {
	EventMetadataExtractor eventinfo.EventMetadataExtractor
	StoredPath             string
	ReleasePath            string
}

// linuxMonitor captures all the monitor processor information
// It implements the EventProcessor interface of the rpc monitor
type linuxMonitor struct {
	collector         collector.EventCollector
	puHandler         monitorimpl.ProcessingUnitsHandler
	syncHandler       monitorimpl.SynchronizationHandler
	metadataExtractor eventinfo.EventMetadataExtractor
	netcls            cgnetcls.Cgroupnetcls
	contextStore      contextstore.ContextStore
	regStart          *regexp.Regexp
	regStop           *regexp.Regexp
	storePath         string
}

// New returns a new implmentation of a monitor implmentation
func New() monitorimpl.Implementation {

	return &linuxMonitor{}
}

// Start implements Implementation interface
func (l *linuxMonitor) Start() error {

	if l.collector == nil {
		return fmt.Errorf("Missing configuration: collector")
	}

	if l.syncHandler == nil {
		return fmt.Errorf("Missing configuration: syncHandler")
	}

	if l.puHandler == nil {
		return fmt.Errorf("Missing configuration: puHandler")
	}

	return nil
}

// Stop implements Implementation interface
func (l *linuxMonitor) Stop() error {

	return nil
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (l *linuxMonitor) SetupConfig(registerer eventserver.Registerer, cfg interface{}) error {

	if cfg == nil {
		cfg = &Config{}
	}

	linuxConfig, ok := cfg.(Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified")
	}

	if registerer != nil {
		registerer.RegisterProcessor(constants.LinuxProcessPU, l)
	}

	if linuxConfig.ReleasePath == "" {
		linuxConfig.ReleasePath = "/var/lib/aporeto/cleaner"
	}

	if linuxConfig.StorePath == "" {
		linuxConfig.StorePath = "/var/run/trireme/linux"
	}

	u.netcls = cgnetcls.NewCgroupNetController(linuxConfig.ReleasePath)
	u.contextStore = contextstore.NewFileContextStore(linuxConfig.StorePath)
	u.storePath = linuxConfig.StorePath

	u.regStart = regexp.MustCompile("^[a-zA-Z0-9_].{0,11}$")
	u.regStop = regexp.MustCompile("^/trireme/[a-zA-Z0-9_].{0,11}$")

	if linuxConfig.EventMetadataExtractor == nil {
		linuxConfig.EventMetadataExtractor = DockerMetadataExtractor
	}
	c.metadataExtractor = linuxConfig.EventMetadataExtractor
	if c.metadataExtractor == nil {
		return fmt.Errorf("Unable to setup a metadata extractor")
	}

	return nil
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (l *linuxMonitor) SetupHandlers(collector trireme.EventCollector, puHandler monitor.ProcessingUnitsHandler, syncHandler monitor.SynchronizationHandler) {

	c.collector = collector
	c.puHandler = puHandler
	c.syncHandler = syncHandler
}

// Create handles create events
func (l *linuxMonitor) Create(eventInfo *eventinfo.EventInfo) error {

	if !s.regStart.Match([]byte(eventInfo.PUID)) {
		return fmt.Errorf("Invalid PU ID %s", eventInfo.PUID)
	}

	return s.puHandler.HandlePUEvent(eventInfo.PUID, monitor.EventCreate)
}

// Start handles start events
func (l *linuxMonitor) Start(eventInfo *eventinfo.EventInfo) error {

	// Validate the PUID format

	if !s.regStart.Match([]byte(eventInfo.PUID)) {
		return fmt.Errorf("Invalid PU ID %s", eventInfo.PUID)
	}

	contextID := eventInfo.PUID
	// Extract the metadata
	runtimeInfo, err := s.metadataExtractor(eventInfo)
	if err != nil {
		return err
	}

	// Setup the run time
	if err = s.puHandler.CreatePURuntime(contextID, runtimeInfo); err != nil {
		return err
	}

	defaultIP, _ := runtimeInfo.DefaultIPAddress()
	if perr := s.puHandler.HandlePUEvent(contextID, monitor.EventStart); perr != nil {
		zap.L().Error("Failed to activate process", zap.Error(perr))
		return perr
	}

	if eventInfo.HostService {
		err = s.processHostServiceStart(eventInfo, runtimeInfo)
	} else {
		err = s.processLinuxServiceStart(eventInfo, runtimeInfo)
	}

	if err != nil {
		return err
	}

	s.collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: defaultIP,
		Tags:      runtimeInfo.Tags(),
		Event:     collector.ContainerStart,
	})

	// Store the state in the context store for future access
	return s.contextStore.Store(contextID, eventInfo)
}

// Stop handles a stop event
func (l *linuxMonitor) Stop(eventInfo *eventinfo.EventInfo) error {

	contextID, err := s.generateContextID(eventInfo)
	if err != nil {
		return err
	}

	if contextID == "/trireme" {
		return nil
	}

	contextID = contextID[strings.LastIndex(contextID, "/")+1:]
	return s.puHandler.HandlePUEvent(contextID, monitor.EventStop)
}

// Destroy handles a destroy event
func (l *linuxMonitor) Destroy(eventInfo *eventinfo.EventInfo) error {

	contextID, err := s.generateContextID(eventInfo)
	if err != nil {
		return err
	}

	if contextID == "/trireme" {
		contextID = strings.TrimLeft(contextID, "/")
		s.netcls.Deletebasepath(contextID)
		return nil
	}

	contextID = contextID[strings.LastIndex(contextID, "/")+1:]

	// Send the event upstream
	if err := s.puHandler.HandlePUEvent(contextID, monitor.EventDestroy); err != nil {
		zap.L().Warn("Failed to clean trireme ",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	if eventInfo.HostService {
		if err := ioutil.WriteFile("/sys/fs/cgroup/net_cls,net_prio/net_cls.classid", []byte("0"), 0644); err != nil {
			return fmt.Errorf("Failed to  write to net_cls.classid file for new cgroup, error %s", err.Error())
		}
	}

	//let us remove the cgroup files now
	if err := s.netcls.DeleteCgroup(contextID); err != nil {
		zap.L().Warn("Failed to clean netcls group",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	if err := s.contextStore.Remove(contextID); err != nil {
		zap.L().Error("Failed to clean cache while destroying process",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	return nil
}

// Pause handles a pause event
func (l *linuxMonitor) Pause(eventInfo *eventinfo.EventInfo) error {

	contextID, err := s.generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	return s.puHandler.HandlePUEvent(contextID, monitor.EventPause)
}

// ReSync resyncs with all the existing services that were there before we start
func (l *linuxMonitor) ReSync(e *eventinfo.EventInfo) error {

	deleted := []string{}
	reacquired := []string{}

	defer func() {
		if len(deleted) > 0 {
			zap.L().Info("Deleted dead contexts", zap.String("Context List", strings.Join(deleted, ",")))
		}
		if len(reacquired) > 0 {
			zap.L().Info("Reacquired contexts", zap.String("Context List", strings.Join(reacquired, ",")))
		}
	}()

	walker, err := s.contextStore.Walk()
	if err != nil {
		return fmt.Errorf("error in accessing context store")
	}

	for {
		contextID := <-walker
		if contextID == "" {
			break
		}

		eventInfo := eventinfo.EventInfo{}
		if err := s.contextStore.Retrieve("/"+contextID, &eventInfo); err != nil {
			continue
		}

		if !eventInfo.HostService {
			processlist, err := cgnetcls.ListCgroupProcesses(eventInfo.PUID)
			if err != nil {
				zap.L().Debug("Removing Context for empty cgroup", zap.String("CONTEXTID", eventInfo.PUID))
				deleted = append(deleted, eventInfo.PUID)
				// The cgroup does not exists - log error and remove context
				if cerr := s.contextStore.Remove(eventInfo.PUID); cerr != nil {
					zap.L().Warn("Failed to remove state from store handler", zap.Error(cerr))
				}
				continue
			}

			if len(processlist) <= 0 {
				// We have an empty cgroup. Remove the cgroup and context store file
				if err := s.netcls.DeleteCgroup(eventInfo.PUID); err != nil {
					zap.L().Warn("Failed to deleted cgroup",
						zap.String("puID", eventInfo.PUID),
						zap.Error(err),
					)
				}
				deleted = append(deleted, eventInfo.PUID)

				if err := s.contextStore.Remove(eventInfo.PUID); err != nil {
					zap.L().Warn("Failed to deleted context",
						zap.String("puID", eventInfo.PUID),
						zap.Error(err),
					)
				}
				continue
			}
		}

		reacquired = append(reacquired, eventInfo.PUID)

		if err := s.Start(&eventInfo); err != nil {
			zap.L().Error("Failed to start PU ", zap.String("PUID", eventInfo.PUID))
			return fmt.Errorf("error in processing existing data: %s", err.Error())
		}

	}

	return nil
}

// generateContextID creates the contextID from the event information
func (l *linuxMonitor) generateContextID(eventInfo *eventinfo.EventInfo) (string, error) {

	contextID := eventInfo.PUID
	if eventInfo.Cgroup != "" {
		if !s.regStop.Match([]byte(eventInfo.Cgroup)) {
			return "", fmt.Errorf("Invalid PUID %s", eventInfo.Cgroup)
		}
		contextID = eventInfo.Cgroup[strings.LastIndex(eventInfo.Cgroup, "/")+1:]
	}
	//contextID = contextID[strings.LastIndex(eventInfo.Cgroup, "/")+1:]
	return contextID, nil
}

func (l *linuxMonitor) processLinuxServiceStart(event *eventinfo.EventInfo, runtimeInfo *policy.PURuntime) error {
	list, err := cgnetcls.ListCgroupProcesses(event.PUID)
	if err == nil {
		//cgroup exists and pid might be a member
		isrestart := func() bool {
			for _, element := range list {
				if element == event.PID {
					//pid is already there it is restart
					return true
				}
			}
			return false
		}()

		if !isrestart {
			pid, _ := strconv.Atoi(event.PID)
			s.netcls.AddProcess(event.PUID, pid) // nolint
			return nil
		}
	}

	//It is okay to launch this so let us create a cgroup for it
	err = s.netcls.Creategroup(event.PUID)
	if err != nil {
		return err
	}

	markval := runtimeInfo.Options().CgroupMark
	if markval == "" {
		if derr := s.netcls.DeleteCgroup(event.PUID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return errors.New("Mark value not found")
	}

	mark, _ := strconv.ParseUint(markval, 10, 32)
	err = s.netcls.AssignMark(event.PUID, mark)
	if err != nil {
		if derr := s.netcls.DeleteCgroup(event.PUID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return err
	}

	pid, _ := strconv.Atoi(event.PID)
	err = s.netcls.AddProcess(event.PUID, pid)
	if err != nil {

		if derr := s.netcls.DeleteCgroup(event.PUID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}

		return err
	}

	return nil
}

func (l *linuxMonitor) processHostServiceStart(event *eventinfo.EventInfo, runtimeInfo *policy.PURuntime) error {

	if !event.NetworkOnlyTraffic {

		markval := runtimeInfo.Options().CgroupMark
		mark, _ := strconv.ParseUint(markval, 10, 32)
		hexmark := "0x" + (strconv.FormatUint(mark, 16))

		if err := ioutil.WriteFile("/sys/fs/cgroup/net_cls,net_prio/net_cls.classid", []byte(hexmark), 0644); err != nil {
			return errors.New("Failed to  write to net_cls.classid file for new cgroup")
		}
	}

	return nil
}
