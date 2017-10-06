package linuxmonitor

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/contextstore"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
)

// LinuxProcessor captures all the monitor processor information
// It implements the MonitorProcessor interface of the rpc monitor
type LinuxProcessor struct {
	collector         collector.EventCollector
	puHandler         monitor.ProcessingUnitsHandler
	metadataExtractor rpcmonitor.RPCMetadataExtractor
	netcls            cgnetcls.Cgroupnetcls
	contextStore      contextstore.ContextStore
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
	}
}

// NewLinuxProcessor creates a default Linux processor with the standard trireme path
func NewLinuxProcessor(collector collector.EventCollector, puHandler monitor.ProcessingUnitsHandler, metadataExtractor rpcmonitor.RPCMetadataExtractor, releasePath string) *LinuxProcessor {
	return NewCustomLinuxProcessor("/var/run/trireme/linux", collector, puHandler, metadataExtractor, releasePath)
}

// Create handles create events
func (s *LinuxProcessor) Create(eventInfo *rpcmonitor.EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	return s.puHandler.HandlePUEvent(contextID, monitor.EventCreate)
}

// Start handles start events
func (s *LinuxProcessor) Start(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return err
	}

	list, err := cgnetcls.ListCgroupProcesses(eventInfo.PUID)
	if err == nil {
		//cgroup exists and pid might be a member
		isrestart := func() bool {
			for _, element := range list {
				if element == eventInfo.PID {
					//pid is already there it is restart
					return true
				}
			}
			return false
		}()

		if !isrestart {
			pid, _ := strconv.Atoi(eventInfo.PID)
			s.netcls.AddProcess(eventInfo.PUID, pid) // nolint
			return nil
		}
	}

	runtimeInfo, err := s.metadataExtractor(eventInfo)
	if err != nil {
		return err
	}

	if err = s.puHandler.SetPURuntime(contextID, runtimeInfo); err != nil {
		return err
	}

	defaultIP, _ := runtimeInfo.DefaultIPAddress()
	if perr := s.puHandler.HandlePUEvent(contextID, monitor.EventStart); perr != nil {
		zap.L().Error("Failed to activate process", zap.Error(perr))
		return perr
	}

	//It is okay to launch this so let us create a cgroup for it
	err = s.netcls.Creategroup(eventInfo.PUID)
	if err != nil {
		return err
	}

	markval := runtimeInfo.Options().CgroupMark
	if markval == "" {
		if derr := s.netcls.DeleteCgroup(eventInfo.PUID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return errors.New("Mark value not found")
	}

	mark, _ := strconv.ParseUint(markval, 10, 32)
	err = s.netcls.AssignMark(eventInfo.PUID, mark)
	if err != nil {
		if derr := s.netcls.DeleteCgroup(eventInfo.PUID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return err
	}

	pid, _ := strconv.Atoi(eventInfo.PID)
	err = s.netcls.AddProcess(eventInfo.PUID, pid)
	if err != nil {

		if derr := s.netcls.DeleteCgroup(eventInfo.PUID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}

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

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	if !strings.HasPrefix(contextID, cgnetcls.TriremeBasePath) || contextID == cgnetcls.TriremeBasePath {
		return nil
	}

	contextID = contextID[strings.LastIndex(contextID, "/"):]

	return s.puHandler.HandlePUEvent(contextID, monitor.EventStop)
}

// Destroy handles a destroy event
func (s *LinuxProcessor) Destroy(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	if !strings.HasPrefix(contextID, cgnetcls.TriremeBasePath) || contextID == cgnetcls.TriremeBasePath {
		return nil
	}

	contextID = contextID[strings.LastIndex(contextID, "/"):]

	s.netcls.Deletebasepath(contextID)

	// Send the event upstream
	if err := s.puHandler.HandlePUEvent(contextID, monitor.EventDestroy); err != nil {
		zap.L().Warn("Failed to clean trireme ",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	//let us remove the cgroup files now
	if err := s.netcls.DeleteCgroup(contextID); err != nil {
		zap.L().Warn("Failed to clean netcls group",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	if err := s.contextStore.RemoveContext(contextID); err != nil {
		zap.L().Warn("Failed to clean cache while destroying process",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	return nil
}

// Pause handles a pause event
func (s *LinuxProcessor) Pause(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
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

		reacquired = append(reacquired, eventInfo.PUID)

		if err := s.Start(&eventInfo); err != nil {
			zap.L().Error("Failed to start PU ", zap.String("PUID", eventInfo.PUID))
			return fmt.Errorf("error in processing existing data: %s", err.Error())
		}

	}

	return nil
}

// generateContextID creates the contextID from the event information
func generateContextID(eventInfo *rpcmonitor.EventInfo) (string, error) {

	if eventInfo.PUID == "" {
		return "", fmt.Errorf("PUID is empty from eventInfo")
	}

	return eventInfo.PUID, nil
}
