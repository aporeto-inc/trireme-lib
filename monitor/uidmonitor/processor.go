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

const (
	triremeBaseCgroup = "/trireme"
)

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
func NewCustomUIDProcessor(storePath string,
	collector collector.EventCollector,
	puHandler monitor.ProcessingUnitsHandler,
	metadataExtractor rpcmonitor.RPCMetadataExtractor,
	releasePath string) *UIDProcessor {

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
func NewUIDProcessor(collector collector.EventCollector,
	puHandler monitor.ProcessingUnitsHandler,
	metadataExtractor rpcmonitor.RPCMetadataExtractor,
	releasePath string) *UIDProcessor {
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

		if perr := s.puHandler.HandlePUEvent(publishedContextID, monitor.EventStart); perr != nil {
			zap.L().Error("Failed to activate process", zap.Error(perr))
			return perr
		}

		if err = s.processLinuxServiceStart(eventInfo, runtimeInfo); err != nil {
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
			pidlist:            map[string]bool{},
		}
		entry.pidlist[eventInfo.PID] = true
		s.puToPidEntry.Add(contextID, entry)
		s.pidToPU.Add(eventInfo.PID, contextID)
		// Store the state in the context store for future access
		return s.contextStore.StoreContext(contextID, &StoredContext{
			EventInfo: eventInfo,
			MarkVal:   runtimeInfo.Options().CgroupMark,
		})

	}
	pids.(*putoPidEntry).pidlist[eventInfo.PID] = true
	s.pidToPU.Add(eventInfo.PID, eventInfo.PUID)
	err = s.processLinuxServiceStart(eventInfo, pids.(*putoPidEntry).Info)
	return err

}

// Stop handles a stop event
func (s *UIDProcessor) Stop(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := s.generateContextID(eventInfo)
	if err != nil {
		return err
	}
	if contextID == triremeBaseCgroup {
		return nil
	}
	// strtokens := strings.Split(contextID, "/")
	// contextID = "/" + strtokens[len(strtokens)-1]

	s.Lock()
	defer s.Unlock()
	if puid, err := s.pidToPU.Get(contextID); err == nil {
		eventInfo.PUID = puid.(string)
	}

	var publishedContextID string
	if pidlist, err := s.puToPidEntry.Get(contextID); err == nil {
		publishedContextID = pidlist.(*putoPidEntry).publishedContextID
		if len(pidlist.(*putoPidEntry).pidlist) > 1 {
			return nil
		}
	}
	if contextID == triremeBaseCgroup {
		return nil
	}

	return s.puHandler.HandlePUEvent(publishedContextID, monitor.EventStop)

}

// Destroy handles a destroy event
func (s *UIDProcessor) Destroy(eventInfo *rpcmonitor.EventInfo) error {

	if eventInfo.PUID == triremeBaseCgroup {
		return nil

	}

	s.Lock()
	defer s.Unlock()
	contextID, err := s.generateContextID(eventInfo)
	if err != nil {
		return err
	}
	cgroupPath := contextID[:strings.LastIndex(contextID, "/")+1]
	if puid, err := s.pidToPU.Get(contextID[:strings.LastIndex(contextID, "/")+1]); err == nil {
		eventInfo.PUID = puid.(string)
	}

	// strtokens := strings.Split(contextID, "/")
	// contextID = "/" + strtokens[len(strtokens)-1]

	ctx, err := s.puToPidEntry.Get(contextID)
	var publishedContextID string

	if err == nil {
		ctxpidEntry, ok := ctx.(*putoPidEntry)
		if !ok {
			return fmt.Errorf("Unable to cast to pupidEntry !! did not destroy %s", contextID)
		}
		publishedContextID = ctxpidEntry.publishedContextID
		delete(ctxpidEntry.pidlist, cgroupPath)

		if len(ctxpidEntry.pidlist) == 0 {
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
	contextID = contextID[strings.LastIndex(contextID, "/")+1:]
	return contextID, nil
}

func (s *UIDProcessor) processLinuxServiceStart(event *rpcmonitor.EventInfo, runtimeInfo *policy.PURuntime) error {

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

	if err = s.netcls.AssignMark(event.PID, mark); err != nil {
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
