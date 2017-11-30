package uidmonitor

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/cache"
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/internal/contextstore"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/monitor/eventinfo"
	"github.com/aporeto-inc/trireme-lib/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// UIDProcessor captures all the monitor processor information for a UIDLoginPU
// It implements the EventProcessor interface of the rpc monitor
type UIDProcessor struct {
	collector         collector.EventCollector
	puHandler         monitor.ProcessingUnitsHandler
	metadataExtractor eventinfo.EventMetadataExtractor
	netcls            cgnetcls.Cgroupnetcls
	contextStore      contextstore.ContextStore
	regStart          *regexp.Regexp
	regStop           *regexp.Regexp
	storePath         string
	putoPidMap        *cache.Cache
	pidToPU           *cache.Cache
	sync.Mutex
}

const (
	triremeBaseCgroup = "/trireme"
)

//puToPidEntry -- represents an entry to puToPidMap
type puToPidEntry struct {
	pidlist            map[string]bool
	Info               *policy.PURuntime
	publishedContextID string
}

// StoredContext -- struct is the structure of stored contextinfo for uidmonitor
type StoredContext struct {
	MarkVal   string
	EventInfo *eventinfo.EventInfo
}

// New initializes a processor with a custom path
func New(storePath string,
	collector collector.EventCollector,
	puHandler monitor.ProcessingUnitsHandler,
	metadataExtractor eventinfo.EventMetadataExtractor,
	releasePath string) *UIDProcessor {
	if puHandler == nil {
		zap.L().Error("PuHandler cannot be nil")
		return nil
	}
	return &UIDProcessor{
		collector:         collector,
		puHandler:         puHandler,
		metadataExtractor: metadataExtractor,
		netcls:            cgnetcls.NewCgroupNetController(releasePath),
		contextStore:      contextstore.NewFileContextStore(storePath),
		storePath:         storePath,
		regStart:          regexp.MustCompile("^[a-zA-Z0-9_].{0,11}$"),
		regStop:           regexp.MustCompile("^/trireme/[a-zA-Z0-9_].{0,11}$"),
		putoPidMap:        cache.NewCache("putoPidMap"),
		pidToPU:           cache.NewCache("pidToPU"),
	}
}

// Start handles start events
func (s *UIDProcessor) Start(eventInfo *eventinfo.EventInfo) error {
	s.Lock()
	defer s.Unlock()
	contextID := eventInfo.PUID
	pids, err := s.putoPidMap.Get(contextID)
	var runtimeInfo *policy.PURuntime
	if err != nil {
		runtimeInfo, err = s.metadataExtractor(eventInfo)
		if err != nil {
			return err
		}

		publishedContextID := contextID + runtimeInfo.Options().CgroupMark
		// Setup the run time
		if err = s.puHandler.CreatePURuntime(publishedContextID, runtimeInfo); err != nil {
			return err
		}

		defaultIP, _ := runtimeInfo.DefaultIPAddress()
		if perr := s.puHandler.HandlePUEvent(publishedContextID, monitor.EventStart); perr != nil {
			zap.L().Error("Failed to activate process", zap.Error(perr))
			return perr
		}

		if err = s.processLinuxServiceStart(eventInfo, runtimeInfo); err != nil {
			zap.L().Error("processLinuxServiceStart", zap.Error(err))
			return err
		}

		s.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: defaultIP,
			Tags:      runtimeInfo.Tags(),
			Event:     collector.ContainerStart,
		})
		entry := &puToPidEntry{
			Info:               runtimeInfo,
			publishedContextID: publishedContextID,
			pidlist:            map[string]bool{},
		}

		entry.pidlist[eventInfo.PID] = true

		if err := s.putoPidMap.Add(contextID, entry); err != nil {
			zap.L().Warn("Failed to add contextID/PU in the cache", zap.Error(err), zap.String("contextID", contextID))
		}

		if err := s.pidToPU.Add(eventInfo.PID, contextID); err != nil {
			zap.L().Warn("Failed to add eventInfoID/contextID in the cache", zap.Error(err), zap.String("contextID", contextID))
		}
		// Store the state in the context store for future access
		return s.contextStore.Store(contextID, &StoredContext{
			EventInfo: eventInfo,
			MarkVal:   runtimeInfo.Options().CgroupMark,
		})

	}

	pids.(*puToPidEntry).pidlist[eventInfo.PID] = true

	if err := s.pidToPU.Add(eventInfo.PID, eventInfo.PUID); err != nil {
		zap.L().Warn("Failed to add eventInfoPID/eventInfoPUID in the cache", zap.Error(err), zap.String("eventInfo.PID", eventInfo.PID), zap.String("eventInfo.PUID", eventInfo.PUID))
	}

	return s.processLinuxServiceStart(eventInfo, pids.(*puToPidEntry).Info)

}

// Stop handles a stop event and destroy as well. Destroy does nothing for the uid monitor
func (s *UIDProcessor) Stop(eventInfo *eventinfo.EventInfo) error {

	contextID, err := s.generateContextID(eventInfo)
	if err != nil {
		return err
	}

	if contextID == triremeBaseCgroup {
		s.netcls.Deletebasepath(contextID)
		return nil
	}
	s.Lock()
	defer s.Unlock()
	//ignore the leading / here this is a special case for stop where i need to do a reverse lookup
	stoppedpid := strings.TrimLeft(contextID, "/")
	if puid, err := s.pidToPU.Get(stoppedpid); err == nil {
		contextID = puid.(string)
	}

	var publishedContextID string
	if pidlist, err := s.putoPidMap.Get(contextID); err == nil {
		ctx := pidlist.(*puToPidEntry)
		publishedContextID = ctx.publishedContextID
		//Clean pid from both caches
		delete(ctx.pidlist, stoppedpid)

		if err = s.pidToPU.Remove(stoppedpid); err != nil {
			zap.L().Warn("Failed to remove entry in the cache", zap.Error(err), zap.String("stoppedpid", stoppedpid))
		}

		if len(pidlist.(*puToPidEntry).pidlist) != 0 {
			//Only destroy the pid that is being stopped
			return s.netcls.DeleteCgroup(stoppedpid)
		}
		//We are the last here lets send stop
		if err = s.puHandler.HandlePUEvent(publishedContextID, monitor.EventStop); err != nil {
			zap.L().Warn("Failed to stop trireme PU ",
				zap.String("contextID", contextID),
				zap.Error(err),
			)
		}

		if err = s.putoPidMap.Remove(contextID); err != nil {
			zap.L().Warn("Failed to remove entry in the cache", zap.Error(err), zap.String("contextID", contextID))
		}

		if err = s.contextStore.Remove(contextID); err != nil {
			zap.L().Error("Failed to clean cache while destroying process",
				zap.String("contextID", contextID),
				zap.Error(err),
			)
		}

		if err = s.puHandler.HandlePUEvent(publishedContextID, monitor.EventDestroy); err != nil {
			zap.L().Warn("Failed to Destroy clean trireme ",
				zap.String("contextID", contextID),
				zap.Error(err),
			)
		}

		return s.netcls.DeleteCgroup(stoppedpid)
	}

	return nil

}

// Create handles create events
func (s *UIDProcessor) Create(eventInfo *eventinfo.EventInfo) error {

	return s.puHandler.HandlePUEvent(eventInfo.PUID, monitor.EventCreate)
}

// Destroy handles a destroy event
func (s *UIDProcessor) Destroy(eventInfo *eventinfo.EventInfo) error {
	//Destroy is not used for the UIDMonitor since we will destroy when we get stop
	//This is to try and save some time .Stop/Destroy is two RPC calls.
	//We don't define pause on uid monitor so stop is always followed by destroy
	return nil

}

// Pause handles a pause event
func (s *UIDProcessor) Pause(eventInfo *eventinfo.EventInfo) error {

	contextID, err := s.generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	return s.puHandler.HandlePUEvent(contextID, monitor.EventPause)
}

// ReSync resyncs with all the existing services that were there before we start
func (s *UIDProcessor) ReSync(e *eventinfo.EventInfo) error {

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

	walker, err := s.contextStore.Walk()

	if err != nil {
		return fmt.Errorf("error in accessing context store")
	}

	cgroups := cgnetcls.GetCgroupList()

	for _, cgroup := range cgroups {
		pidlist, _ := cgnetcls.ListCgroupProcesses(cgroup)
		if len(pidlist) == 0 {
			if err := s.netcls.DeleteCgroup(cgroup); err != nil {
				zap.L().Warn("Error when deleting cgroup", zap.Error(err), zap.String("cgroup", cgroup))
			}
			continue
		}
		markval := cgnetcls.GetAssignedMarkVal(cgroup)

		if list, ok := marktoPID[markval]; !ok {
			marktoPID[markval] = pidlist
		} else {
			marktoPID[markval] = append(list, pidlist...)
		}
	}

	for {
		contextID := <-walker
		if contextID == "" {
			break
		}

		storedPU := &StoredContext{}

		if err := s.contextStore.Retrieve("/"+contextID, &storedPU); err != nil {
			continue
		}
		eventInfo := storedPU.EventInfo
		mark := storedPU.MarkVal
		if pids, ok := marktoPID[mark]; !ok {
			//No pids with stored mark destroy the context record and go to next context
			if err := s.contextStore.Remove("/" + contextID); err != nil {
				zap.L().Warn("Error when removing context in the store", zap.Error(err))
			}
		} else {
			for _, pid := range pids {
				eventInfo.PID = pid
				if err := s.Start(eventInfo); err != nil {
					zap.L().Error("Error when restarting uid pu", zap.Error(err), zap.String("eventInfoPID", eventInfo.PID))
				}
			}
		}
	}

	return nil
}

// generateContextID creates the contextID from the event information
func (s *UIDProcessor) generateContextID(eventInfo *eventinfo.EventInfo) (string, error) {

	contextID := eventInfo.PUID
	if eventInfo.Cgroup != "" {
		if !s.regStop.Match([]byte(eventInfo.Cgroup)) {
			return "", fmt.Errorf("Invalid PUID %s", eventInfo.Cgroup)
		}
		contextID = eventInfo.Cgroup[strings.LastIndex(eventInfo.Cgroup, "/")+1:]
	}
	contextID = "/" + contextID[strings.LastIndex(contextID, "/")+1:]
	return contextID, nil
}

func (s *UIDProcessor) processLinuxServiceStart(event *eventinfo.EventInfo, runtimeInfo *policy.PURuntime) error {

	//It is okay to launch this so let us create a cgroup for it
	if err := s.netcls.Creategroup(event.PID); err != nil {
		return err
	}

	markval := runtimeInfo.Options().CgroupMark
	if markval == "" {
		if derr := s.netcls.DeleteCgroup(event.PID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return errors.New("Mark value not found")
	}

	mark, err := strconv.ParseUint(markval, 10, 32)

	if err != nil {
		return err
	}

	if err = s.netcls.AssignMark(event.PID, mark); err != nil {
		if derr := s.netcls.DeleteCgroup(event.PID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return err
	}

	pid, err := strconv.Atoi(event.PID)

	if err != nil {
		return err
	}

	if err := s.netcls.AddProcess(event.PID, pid); err != nil {

		if derr := s.netcls.DeleteCgroup(event.PID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}

		return err
	}

	return nil
}
