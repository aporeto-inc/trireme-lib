package uidmonitor

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/contextstore"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
	"github.com/aporeto-inc/trireme/policy"
)

// UIDProcessor captures all the monitor processor information for a UIDLoginPU
// It implements the MonitorProcessor interface of the rpc monitor
type UIDProcessor struct {
	collector         collector.EventCollector
	puHandler         monitor.ProcessingUnitsHandler
	metadataExtractor rpcmonitor.RPCMetadataExtractor
	netcls            cgnetcls.Cgroupnetcls
	contextStore      contextstore.ContextStore
	regStart          *regexp.Regexp
	regStop           *regexp.Regexp
	storePath         string
	puToPidEntry      *cache.Cache
	pidToPU           *cache.Cache
	sync.Mutex
}

type putoPidEntry struct {
	pidlist            map[string]bool
	Info               *policy.PURuntime
	publishedContextID string
}

// StoredContext -- struct is the structure of stored contextinfo for uidmonitor
type StoredContext struct {
	MarkVal   string
	EventInfo *rpcmonitor.EventInfo
}

// NewCustomUIDProcessor initializes a processor with a custom path
func NewCustomUIDProcessor(storePath string, collector collector.EventCollector, puHandler monitor.ProcessingUnitsHandler, metadataExtractor rpcmonitor.RPCMetadataExtractor, releasePath string) *UIDProcessor {

	return &UIDProcessor{
		collector:         collector,
		puHandler:         puHandler,
		metadataExtractor: metadataExtractor,
		netcls:            cgnetcls.NewCgroupNetController(releasePath),
		contextStore:      contextstore.NewContextStore(storePath),
		storePath:         storePath,
		regStart:          regexp.MustCompile("^[a-zA-Z0-9_].{0,11}$"),
		regStop:           regexp.MustCompile("^/trireme/[a-zA-Z0-9_].{0,11}$"),
		puToPidEntry:      cache.NewCache(),
		pidToPU:           cache.NewCache(),
	}
}

// NewUIDProcessor creates a default Linux processor with the standard trireme path
func NewUIDProcessor(collector collector.EventCollector, puHandler monitor.ProcessingUnitsHandler, metadataExtractor rpcmonitor.RPCMetadataExtractor, releasePath string) *UIDProcessor {
	return NewCustomUIDProcessor("/var/run/trireme/linux", collector, puHandler, metadataExtractor, releasePath)
}

// Create handles create events
func (s *UIDProcessor) Create(eventInfo *rpcmonitor.EventInfo) error {

	return s.puHandler.HandlePUEvent(eventInfo.PUID, monitor.EventCreate)
}

// Start handles start events
func (s *UIDProcessor) Start(eventInfo *rpcmonitor.EventInfo) error {
	s.Lock()
	defer s.Unlock()
	contextID := eventInfo.PUID
	pids, err := s.puToPidEntry.Get(contextID)
	var runtimeInfo *policy.PURuntime
	if err != nil {
		runtimeInfo, err = s.metadataExtractor(eventInfo)
		if err != nil {
			return err
		}
		publishedContextID := contextID + runtimeInfo.Options().CgroupMark
		// Setup the run time
		if err = s.puHandler.SetPURuntime(publishedContextID, runtimeInfo); err != nil {
			return err
		}

		defaultIP, _ := runtimeInfo.DefaultIPAddress()

		zap.L().Error("Starting ", zap.String("contextID", contextID), zap.String("Publishing", publishedContextID))
		if perr := s.puHandler.HandlePUEvent(publishedContextID, monitor.EventStart); perr != nil {
			zap.L().Error("Failed to activate process", zap.Error(perr))
			return perr
		}

		err = s.processLinuxServiceStart(eventInfo, runtimeInfo)

		if err != nil {
			zap.L().Error("ProcessLInuxServiceStart", zap.Error(err))
			return err
		}

		s.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: defaultIP,
			Tags:      runtimeInfo.Tags(),
			Event:     collector.ContainerStart,
		})
		entry := &putoPidEntry{
			Info:               runtimeInfo,
			publishedContextID: publishedContextID,
		}
		entry.pidlist = make(map[string]bool, 20)
		entry.pidlist[eventInfo.PID] = true
		s.puToPidEntry.Add(contextID, entry)
		s.pidToPU.Add(eventInfo.PID, contextID)
		// Store the state in the context store for future access
		zap.L().Error("ContextID", zap.String("eventInfo.PID", eventInfo.PID), zap.String("eventInfo.OUID", contextID))
		return s.contextStore.StoreContext(contextID, &StoredContext{
			EventInfo: eventInfo,
			MarkVal:   runtimeInfo.Options().CgroupMark,
		})

	}
	zap.L().Error("Adding to existing session", zap.String("contextID", contextID))
	pids.(*putoPidEntry).pidlist[eventInfo.PID] = true
	s.pidToPU.Add(eventInfo.PID, eventInfo.PUID)
	err = s.processLinuxServiceStart(eventInfo, pids.(*putoPidEntry).Info)
	return err

}

// Stop handles a stop event
func (s *UIDProcessor) Stop(eventInfo *rpcmonitor.EventInfo) error {
	if eventInfo.PUID == "/trireme" {
		return nil
	}
	contextID, err := s.generateContextID(eventInfo)
	if err != nil {
		return err
	}
	strtokens := strings.Split(contextID, "/")
	contextID = "/" + strtokens[len(strtokens)-1]
	zap.L().Error("UID STOP EventInfo", zap.String("EventInfo.PUID", event.PUID),
		zap.String("EventInfo.PID", event.PID),
		zap.String("EventType", string(event.EventType)),
		zap.Bool("HostService", event.HostService),
		zap.String("CGROUP", event.Cgroup),
	)
	zap.L().Error("EventInfo.PUID", zap.String("PUID", eventInfo.PUID))
	s.Lock()
	defer s.Unlock()
	stoppedpid := strings.Split(eventInfo.PUID, "/")[2]
	if puid, err := s.pidToPU.Get(stoppedpid); err == nil {
		eventInfo.PUID = puid.(string)
	}

	var publishedContextID string
	zap.L().Error("167", zap.String("contextID", contextID))
	if pidlist, err := s.puToPidEntry.Get(contextID); err == nil {
		publishedContextID = pidlist.(*putoPidEntry).publishedContextID
		if len(pidlist.(*putoPidEntry).pidlist) > 1 {
			zap.L().Error("Length of PIDLIST", zap.Int("Length", len(pidlist.(*putoPidEntry).pidlist)))
			return nil
		}
	}
	if len(strtokens) == 1 && contextID == "trireme" {
		return nil
	}

	hperr := s.puHandler.HandlePUEvent(publishedContextID, monitor.EventStop)
	zap.L().Error("Stopped contextID ", zap.String("contextID", contextID), zap.String("PID", stoppedpid))
	return hperr
}

// Destroy handles a destroy event
func (s *UIDProcessor) Destroy(eventInfo *rpcmonitor.EventInfo) error {

	if eventInfo.PUID == "/trireme" {
		return nil

	}
	cgroupPath := strings.Split(eventInfo.PUID, "/")[2]
	zap.L().Error("Called Destroy", zap.String("contextID", eventInfo.PUID), zap.String("PID", cgroupPath))
	var puid string
	s.Lock()
	defer s.Unlock()
	if puid, err := s.pidToPU.Get(strings.Split(eventInfo.PUID, "/")[2]); err == nil {
		eventInfo.PUID = puid.(string)
	}

	contextID, err := s.generateContextID(eventInfo)
	if err != nil {
		return err
	}
	strtokens := strings.Split(contextID, "/")
	contextID = "/" + strtokens[len(strtokens)-1]

	zap.L().Error("Destroying PU", zap.String("contextID", contextID), zap.String("PID", cgroupPath))
	ctx, err := s.puToPidEntry.Get(contextID)
	var publishedContextID string

	if err == nil {

		publishedContextID = ctx.(*putoPidEntry).publishedContextID
		delete(ctx.(*putoPidEntry).pidlist, cgroupPath)

		if len(ctx.(*putoPidEntry).pidlist) == 0 {
			zap.L().Error("Removed context", zap.String("contextID", contextID))
			s.puToPidEntry.Remove(contextID)
			if err = s.contextStore.RemoveContext(contextID); err != nil {
				zap.L().Error("Failed to clean cache while destroying process",
					zap.String("contextID", contextID),
					zap.Error(err),
				)
			}

			s.netcls.DeleteCgroup(cgroupPath)

		} else {
			s.netcls.DeleteCgroup(cgroupPath)
			if err != nil {
				zap.L().Error("Did not Find Context", zap.String("PUID", puid))
			}

			return nil
		}
		//s.Unlock()

	}
	s.netcls.Deletebasepath(contextID)
	// Send the event upstream
	if err := s.puHandler.HandlePUEvent(publishedContextID, monitor.EventDestroy); err != nil {
		zap.L().Warn("Failed to clean trireme ",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	return nil
}

// Pause handles a pause event
func (s *UIDProcessor) Pause(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := s.generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	return s.puHandler.HandlePUEvent(contextID, monitor.EventPause)
}

// ReSync resyncs with all the existing services that were there before we start
func (s *UIDProcessor) ReSync(e *rpcmonitor.EventInfo) error {

	deleted := []string{}
	reacquired := []string{}
	marktoPID := map[string][]string{}
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
	cgroups := cgnetcls.GetCgroupList()
	for _, cgroup := range cgroups {
		pidlist, _ := cgnetcls.ListCgroupProcesses(cgroup)
		if len(pidlist) == 0 {
			s.netcls.DeleteCgroup(cgroup)
			continue
		}
		markval := cgnetcls.GetAssignedMarkVal(cgroup)
		if list, ok := marktoPID[markval]; !ok {
			marktoPID[markval] = pidlist
		} else {
			marktoPID[markval] = append(list, pidlist...)
		}
	}
	for k, v := range marktoPID {
		zap.L().Error("Context ID", zap.String("Key", k), zap.String("PIDS", strings.Join(v, ",")))
	}
	for {
		contextID := <-walker
		if contextID == "" {
			break
		}

		storedPU := &StoredContext{}

		if err := s.contextStore.GetContextInfo("/"+contextID, &storedPU); err != nil {
			continue
		}
		eventInfo := storedPU.EventInfo
		mark := storedPU.MarkVal
		if pids, ok := marktoPID[mark]; !ok {
			//No pids with stored mark destroy the context record and go to next context
			s.contextStore.RemoveContext("/" + contextID)
			continue
		} else {
			for _, pid := range pids {
				eventInfo.PID = pid
				s.Start(eventInfo)
			}
		}

	}

	return nil
}

// generateContextID creates the contextID from the event information
func (s *UIDProcessor) generateContextID(eventInfo *rpcmonitor.EventInfo) (string, error) {

	contextID := eventInfo.PUID
	if eventInfo.Cgroup != "" {
		if !s.regStop.Match([]byte(eventInfo.Cgroup)) {
			return "", fmt.Errorf("Invalid PUID %s", eventInfo.Cgroup)
		}
		contextID = eventInfo.Cgroup[strings.LastIndex(eventInfo.Cgroup, "/")+1:]
	}

	return contextID, nil
}

func (s *UIDProcessor) processLinuxServiceStart(event *rpcmonitor.EventInfo, runtimeInfo *policy.PURuntime) error {
	// list, err := cgnetcls.ListCgroupProcesses(event.PUID)
	// if err == nil {
	// 	//cgroup exists and pid might be a member
	// 	isrestart := func() bool {
	// 		for _, element := range list {
	// 			if element == event.PID {
	// 				//pid is already there it is restart
	// 				return true
	// 			}
	// 		}
	// 		return false
	// 	}()

	// 	if !isrestart {
	// 		pid, _ := strconv.Atoi(event.PID)
	// 		s.netcls.AddProcess(event.PID, pid) // nolint
	// 		return nil
	// 	}
	// }

	//It is okay to launch this so let us create a cgroup for it
	err := s.netcls.Creategroup(event.PID)
	if err != nil {
		return err
	}

	markval := runtimeInfo.Options().CgroupMark
	if markval == "" {
		if derr := s.netcls.DeleteCgroup(event.PID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return errors.New("Mark value not found")
	}

	mark, _ := strconv.ParseUint(markval, 10, 32)
	err = s.netcls.AssignMark(event.PID, mark)
	if err != nil {
		if derr := s.netcls.DeleteCgroup(event.PID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return err
	}

	pid, _ := strconv.Atoi(event.PID)
	err = s.netcls.AddProcess(event.PID, pid)
	if err != nil {

		if derr := s.netcls.DeleteCgroup(event.PID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}

		return err
	}

	return nil
}
