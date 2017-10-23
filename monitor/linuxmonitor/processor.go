package linuxmonitor

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/contextstore"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
	"github.com/aporeto-inc/trireme/policy"
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
	puToPidEntry      *cache.Cache
	pidToPU           *cache.Cache
	sync.Mutex
}

type putoPidEntry struct {
	pidlist            map[string]bool
	Info               *policy.PURuntime
	publishedContextID string
}

type StoredContext struct {
	MarkVal   string
	EventInfo *rpcmonitor.EventInfo
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
		puToPidEntry:      cache.NewCache(),
		pidToPU:           cache.NewCache(),
	}
}

// NewLinuxProcessor creates a default Linux processor with the standard trireme path
func NewLinuxProcessor(collector collector.EventCollector, puHandler monitor.ProcessingUnitsHandler, metadataExtractor rpcmonitor.RPCMetadataExtractor, releasePath string) *LinuxProcessor {
	return NewCustomLinuxProcessor("/var/run/trireme/linux", collector, puHandler, metadataExtractor, releasePath)
}

// Create handles create events
func (s *LinuxProcessor) Create(eventInfo *rpcmonitor.EventInfo) error {

	if !s.regStart.Match([]byte(eventInfo.PUID)) && eventInfo.PUType != constants.UIDLoginPU {
		return fmt.Errorf("Invalid PU ID %s", eventInfo.PUID)
	}
	zap.L().Error("Create", zap.String("PUID", eventInfo.PUID))
	return s.puHandler.HandlePUEvent(eventInfo.PUID, monitor.EventCreate)
}

func (s *LinuxProcessor) ProcessUIDLoginStart(eventInfo *rpcmonitor.EventInfo) error {
	s.Lock()
	defer s.Unlock()
	contextID := eventInfo.PUID
	pids, err := s.puToPidEntry.Get(contextID)

	if err != nil {
		zap.L().Error("Creating a new uidsesion", zap.String("ContextID", contextID), zap.String("PID", eventInfo.PID))
		runtimeInfo, err := s.metadataExtractor(eventInfo)
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

	} else {
		zap.L().Error("Adding to existing session", zap.String("contextID", contextID))
		//pids.(*putoPidEntry).pidlist = append(pids.(*putoPidEntry).pidlist, eventInfo.PID)

		pids.(*putoPidEntry).pidlist[eventInfo.PID] = true
		//s.puToPidEntry.AddOrUpdate(contextID, pids)
		s.pidToPU.Add(eventInfo.PID, eventInfo.PUID)
		err = s.processLinuxServiceStart(eventInfo, pids.(*putoPidEntry).Info)
		if err != nil {
			return err
		}
		return nil
	}

}

// Start handles start events
func (s *LinuxProcessor) Start(eventInfo *rpcmonitor.EventInfo) error {

	// Validate the PUID format
	if !s.regStart.Match([]byte(eventInfo.PUID)) && eventInfo.PUType != constants.UIDLoginPU {
		return fmt.Errorf("Invalid PU ID %s", eventInfo.PUID)
	}

	contextID := eventInfo.PUID

	if eventInfo.PUType == constants.UIDLoginPU {
		return s.ProcessUIDLoginStart(eventInfo)
	}
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
	zap.L().Error("Starting ", zap.String("contextID", contextID))
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
	zap.L().Error("ContextID", zap.String("context", contextID), zap.String("eventInfo.Name", eventInfo.Name))
	return s.contextStore.StoreContext(contextID, &StoredContext{
		MarkVal:   runtimeInfo.Options().CgroupMark,
		EventInfo: eventInfo,
	})
}
func (s *LinuxProcessor) getContextIDFromPID(pid string) (string, error) {
	data, _ := ioutil.ReadFile("/proc/" + pid + "/status")
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Uid:") {
			uids := strings.Split(strings.Split(line, ":")[1], "\t")
			zap.L().Error("Looking up uid ", zap.String("UID", uids[1]))
			user, _ := user.LookupId(uids[1])
			return "/" + user.Username, nil
		}
	}
	return "", fmt.Errorf("Bad Format for pid")
}

// Stop handles a stop event
func (s *LinuxProcessor) Stop(eventInfo *rpcmonitor.EventInfo) error {
	if eventInfo.PUID == "/trireme" {
		return nil
	}
	zap.L().Error("EventInfo.PUID", zap.String("PUID", eventInfo.PUID))
	s.Lock()
	defer s.Unlock()
	stoppedpid := strings.Split(eventInfo.PUID, "/")[2]
	if puid, err := s.pidToPU.Get(stoppedpid); err == nil {
		eventInfo.PUID = puid.(string)
	}

	contextID, err := s.generateContextID(eventInfo)
	if err != nil {
		return err
	}
	strtokens := strings.Split(contextID, "/")
	contextID = "/" + strtokens[len(strtokens)-1]
	var publishedContextID string

	if pidlist, err := s.puToPidEntry.Get(contextID); err == nil {
		//delete(pidlist.(*putoPidEntry).pidlist, stoppedpid)

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
func (s *LinuxProcessor) Destroy(eventInfo *rpcmonitor.EventInfo) error {

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
			if err := s.contextStore.RemoveContext(contextID); err != nil {
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

	if eventInfo.HostService {
		if err := ioutil.WriteFile("/sys/fs/cgroup/net_cls,net_prio/net_cls.classid", []byte("0"), 0644); err != nil {
			return fmt.Errorf("Failed to  write to net_cls.classid file for new cgroup, error %s", err.Error())
		}
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

	for {
		contextID := <-walker
		if contextID == "" {
			break
		}

		//eventInfo := rpcmonitor.EventInfo{}
		storedPU := &StoredContext{}

		if err := s.contextStore.GetContextInfo("/"+contextID, &storedPU); err != nil {
			continue
		}
		eventInfo := storedPU.EventInfo
		if !eventInfo.HostService && eventInfo.PUType != constants.UIDLoginPU {
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
		if constants.UIDLoginPU == eventInfo.PUType {
			//Build a map of all pu to markval

			//Let populate
			var markval string
			processlist := []string{}
			cgroupList := cgnetcls.GetCgroupList()
			for _, cgroup := range cgroupList {
				markval = cgnetcls.GetAssignedMarkVal(cgroup)
				processlist, _ = cgnetcls.ListCgroupProcesses(cgroup)

			}
			if val, ok := marktoPID[markval]; !ok {
				marktoPID[markval] = []string{markval}
			} else {
				marktoPID[markval] = append(marktoPID[markval], processlist...)
			}

		}
		reacquired = append(reacquired, eventInfo.PUID)

		if err := s.Start(eventInfo); err != nil {
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

	return contextID, nil
}

func (s *LinuxProcessor) processLinuxServiceStart(event *rpcmonitor.EventInfo, runtimeInfo *policy.PURuntime) error {
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
