package linuxmonitor

import (
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/monitor/contextstore"
	"github.com/aporeto-inc/trireme-lib/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme-lib/monitor/rpcmonitor"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// LinuxProcessor captures all the monitor processor information
// It implements the MonitorProcessor interface of the rpc monitor
type LinuxProcessor struct {
	collector         collector.EventCollector
	puHandler         monitor.ProcessingUnitsHandler
	metadataExtractor rpcmonitor.RPCMetadataExtractor
	netcls            cgnetcls.Cgroupnetcls
	contextStore      contextstore.ContextStore
	regStart          *regexp.Regexp
	regStop           *regexp.Regexp
	storePath         string
}

// NewCustomLinuxProcessor initializes a processor with a custom path
func NewCustomLinuxProcessor(storePath string, collector collector.EventCollector, puHandler monitor.ProcessingUnitsHandler, metadataExtractor rpcmonitor.RPCMetadataExtractor, releasePath string) *LinuxProcessor {

	return &LinuxProcessor{
		collector:         collector,
		puHandler:         puHandler,
		metadataExtractor: metadataExtractor,
		netcls:            cgnetcls.NewCgroupNetController(releasePath),
		contextStore:      contextstore.NewContextStore(storePath),
		storePath:         storePath,
		regStart:          regexp.MustCompile("^[a-zA-Z0-9_].{0,11}$"),
		regStop:           regexp.MustCompile("^/trireme/[a-zA-Z0-9_].{0,11}$"),
	}
}

// NewLinuxProcessor creates a default Linux processor with the standard trireme path
func NewLinuxProcessor(collector collector.EventCollector, puHandler monitor.ProcessingUnitsHandler, metadataExtractor rpcmonitor.RPCMetadataExtractor, releasePath string) *LinuxProcessor {
	return NewCustomLinuxProcessor("/var/run/trireme/linux", collector, puHandler, metadataExtractor, releasePath)
}

// Create handles create events
func (s *LinuxProcessor) Create(eventInfo *rpcmonitor.EventInfo) error {

	if !s.regStart.Match([]byte(eventInfo.PUID)) {
		return fmt.Errorf("Invalid PU ID %s", eventInfo.PUID)
	}

	return s.puHandler.HandlePUEvent(eventInfo.PUID, monitor.EventCreate)
}

// Start handles start events
func (s *LinuxProcessor) Start(eventInfo *rpcmonitor.EventInfo) error {

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
	if err = s.puHandler.SetPURuntime(contextID, runtimeInfo); err != nil {
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
	return s.contextStore.StoreContext(contextID, eventInfo)
}

// Stop handles a stop event
func (s *LinuxProcessor) Stop(eventInfo *rpcmonitor.EventInfo) error {

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
func (s *LinuxProcessor) Destroy(eventInfo *rpcmonitor.EventInfo) error {

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

	if err := s.contextStore.RemoveContext(contextID); err != nil {
		zap.L().Error("Failed to clean cache while destroying process",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	return nil
}

// Pause handles a pause event
func (s *LinuxProcessor) Pause(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := s.generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	return s.puHandler.HandlePUEvent(contextID, monitor.EventPause)
}

// ReSync resyncs with all the existing services that were there before we start
func (s *LinuxProcessor) ReSync(e *rpcmonitor.EventInfo) error {

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

	walker, err := s.contextStore.WalkStore()
	if err != nil {
		return fmt.Errorf("error in accessing context store")
	}

	for {
		contextID := <-walker
		if contextID == "" {
			break
		}

		eventInfo := rpcmonitor.EventInfo{}
		if err := s.contextStore.GetContextInfo("/"+contextID, &eventInfo); err != nil {
			continue
		}

		if !eventInfo.HostService {
			processlist, err := cgnetcls.ListCgroupProcesses(eventInfo.PUID)
			if err != nil {
				zap.L().Debug("Removing Context for empty cgroup", zap.String("CONTEXTID", eventInfo.PUID))
				deleted = append(deleted, eventInfo.PUID)
				// The cgroup does not exists - log error and remove context
				if cerr := s.contextStore.RemoveContext(eventInfo.PUID); cerr != nil {
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

				if err := s.contextStore.RemoveContext(eventInfo.PUID); err != nil {
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
func (s *LinuxProcessor) generateContextID(eventInfo *rpcmonitor.EventInfo) (string, error) {

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

func (s *LinuxProcessor) processLinuxServiceStart(event *rpcmonitor.EventInfo, runtimeInfo *policy.PURuntime) error {
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

func (s *LinuxProcessor) processHostServiceStart(event *rpcmonitor.EventInfo, runtimeInfo *policy.PURuntime) error {

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
