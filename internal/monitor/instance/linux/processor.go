package linuxmonitor

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/rpc/events"
	"github.com/aporeto-inc/trireme-lib/rpc/processor"
	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls"
	"github.com/aporeto-inc/trireme-lib/utils/contextstore"
)

// StoredContext is the information stored to retrieve the context in case of restart.
type StoredContext struct {
	EventInfo *events.EventInfo
	Tags      *policy.TagStore `json:"Tags,omitempty"`
}

// linuxProcessor captures all the monitor processor information
// It implements the EventProcessor interface of the rpc monitor
type linuxProcessor struct {
	host              bool
	config            *processor.Config
	metadataExtractor events.EventMetadataExtractor
	netcls            cgnetcls.Cgroupnetcls
	contextStore      contextstore.ContextStore
	regStart          *regexp.Regexp
	regStop           *regexp.Regexp
	storePath         string
}

func baseName(name, separator string) string {

	lastseparator := strings.LastIndex(name, separator)
	if len(name) <= lastseparator {
		return ""
	}
	return name[lastseparator+1:]
}

// RemapData Remaps the contextstore data from an old format to the newer format.
func (l *linuxProcessor) RemapData(data string, fixedData interface{}) error {
	event := &events.EventInfo{}

	if err := json.Unmarshal([]byte(data), event); err != nil {
		return fmt.Errorf("Received error %s while remapping data", err)
	}
	sc, ok := fixedData.(*StoredContext)
	if !ok {
		return fmt.Errorf("Invalid data type")
	}
	if sc.Tags == nil {
		sc.Tags = policy.NewTagStore()
	}
	sc.EventInfo = event
	return nil
}

// Create handles create events
func (l *linuxProcessor) Create(eventInfo *events.EventInfo) error {

	if !l.regStart.Match([]byte(eventInfo.PUID)) {
		return fmt.Errorf("invalid pu id: %s", eventInfo.PUID)
	}

	return l.config.PUHandler.HandlePUEvent(eventInfo.PUID, events.EventCreate)
}

// startInternal is called while starting and reacquiring.
func (l *linuxProcessor) startInternal(runtimeInfo *policy.PURuntime, eventInfo *events.EventInfo) (err error) {

	// Validate the PUID format
	if !l.regStart.Match([]byte(eventInfo.PUID)) {
		return fmt.Errorf("invalid pu id: %s", eventInfo.PUID)
	}

	// Setup the run time
	if err = l.config.PUHandler.CreatePURuntime(eventInfo.PUID, runtimeInfo); err != nil {
		return fmt.Errorf("create runtime failed: %s", err)
	}

	if err = l.config.PUHandler.HandlePUEvent(eventInfo.PUID, events.EventStart); err != nil {
		return fmt.Errorf("handle pu failed: %s", err)
	}

	if eventInfo.HostService {
		err = l.processHostServiceStart(eventInfo, runtimeInfo)
	} else {
		err = l.processLinuxServiceStart(eventInfo, runtimeInfo)
	}
	if err != nil {
		return fmt.Errorf("start pu failed: %s", err)
	}

	defaultIP, _ := runtimeInfo.DefaultIPAddress()
	l.config.Collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: eventInfo.PUID,
		IPAddress: defaultIP,
		Tags:      runtimeInfo.Tags(),
		Event:     collector.ContainerStart,
	})

	// Store the state in the context store for future access
	return l.contextStore.Store(eventInfo.PUID, &StoredContext{
		EventInfo: eventInfo,
		Tags:      runtimeInfo.Tags(),
	})
}

// Start handles start events
func (l *linuxProcessor) Start(eventInfo *events.EventInfo) error {

	// Extract the metadata
	runtimeInfo, err := l.metadataExtractor(eventInfo)
	if err != nil {
		return err
	}

	return l.startInternal(runtimeInfo, eventInfo)
}

// Stop handles a stop event
func (l *linuxProcessor) Stop(eventInfo *events.EventInfo) error {

	contextID, err := l.generateContextID(eventInfo)
	if err != nil {
		return err
	}

	if contextID == "/trireme" {
		return nil
	}

	contextID = baseName(contextID, "/")
	return l.config.PUHandler.HandlePUEvent(contextID, events.EventStop)
}

// Destroy handles a destroy event
func (l *linuxProcessor) Destroy(eventInfo *events.EventInfo) error {

	contextID, err := l.generateContextID(eventInfo)
	if err != nil {
		return err
	}

	if contextID == "/trireme" {
		contextID = strings.TrimLeft(contextID, "/")
		l.netcls.Deletebasepath(contextID)
		return nil
	}

	contextID = baseName(contextID, "/")

	// Send the event upstream
	if err := l.config.PUHandler.HandlePUEvent(contextID, events.EventDestroy); err != nil {
		zap.L().Warn("Unable to clean trireme ",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	if eventInfo.HostService {
		if err := ioutil.WriteFile("/sys/fs/cgroup/net_cls,net_prio/net_cls.classid", []byte("0"), 0644); err != nil {
			return fmt.Errorf("unable to write to net_cls.classid file for new cgroup: %s", err)
		}
	}

	//let us remove the cgroup files now
	if err := l.netcls.DeleteCgroup(contextID); err != nil {
		zap.L().Warn("Failed to clean netcls group",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	if err := l.contextStore.Remove(contextID); err != nil {
		zap.L().Error("Failed to clean cache while destroying process",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	return nil
}

// Pause handles a pause event
func (l *linuxProcessor) Pause(eventInfo *events.EventInfo) error {

	contextID, err := l.generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("unable to generate context id: %s", err)
	}

	return l.config.PUHandler.HandlePUEvent(contextID, events.EventPause)
}

// ReSync resyncs with all the existing services that were there before we start
func (l *linuxProcessor) ReSync(e *events.EventInfo) error {

	deleted := []string{}
	reacquired := []string{}

	retrieveFailed := 0
	metadataExtractionFailed := 0
	syncFailed := 0
	puStartFailed := 0
	invalidContextWithNoTags := 0
	newPUCreated := 0

	defer func() {
		if retrieveFailed == 0 &&
			metadataExtractionFailed == 0 &&
			syncFailed == 0 &&
			puStartFailed == 0 &&
			invalidContextWithNoTags == 0 &&
			newPUCreated == 0 {
			zap.L().Debug("Linux process resync completed",
				zap.Bool("host", l.host),
				zap.Strings("deleted", deleted),
				zap.Strings("reacquired", reacquired),
			)
		} else {
			zap.L().Warn("Linux process resync completed with failures",
				zap.Bool("host", l.host),
				zap.Strings("deleted", deleted),
				zap.Strings("reacquired", reacquired),
				zap.Int("retrieve-failed", retrieveFailed),
				zap.Int("metadata-extraction-failed", metadataExtractionFailed),
				zap.Int("sync-failed", syncFailed),
				zap.Int("start-failed", puStartFailed),
				zap.Int("invalidContextWithNoTags", invalidContextWithNoTags),
				zap.Int("newPUCreated", newPUCreated),
			)
		}
	}()

	walker, err := l.contextStore.Walk()
	if err != nil {
		return fmt.Errorf("unable to walk context store: %s", err)
	}

	for {

		contextID := <-walker
		if contextID == "" {
			break
		}

		// Get contexts, runtime, eventinfo, etc ..
		storedContext := StoredContext{}
		if err := l.contextStore.Retrieve("/"+contextID, &storedContext); err != nil {
			retrieveFailed++
			continue
		}
		if storedContext.Tags == nil {
			invalidContextWithNoTags++
			continue
		}

		// Add specific tags
		eventInfo := storedContext.EventInfo
		for _, t := range l.config.MergeTags {
			if val, ok := storedContext.Tags.Get(t); ok {
				eventInfo.Tags = append(eventInfo.Tags, t+"="+val)
			}
		}
		runtimeInfo, err := l.metadataExtractor(eventInfo)
		if err != nil {
			metadataExtractionFailed++
			return err
		}
		t := runtimeInfo.Tags()
		if t != nil && storedContext.Tags != nil {
			t.Merge(storedContext.Tags)
			runtimeInfo.SetTags(t)
		}

		if !eventInfo.HostService {

			processlist, err := cgnetcls.ListCgroupProcesses(eventInfo.PUID)
			if err != nil {
				deleted = append(deleted, eventInfo.PUID)
				if err := l.contextStore.Remove(eventInfo.PUID); err != nil {
					zap.L().Warn("Failed to remove state from store handler",
						zap.String("puID", eventInfo.PUID),
						zap.Error(err))
				}
				continue
			}

			if len(processlist) <= 0 {

				deleted = append(deleted, eventInfo.PUID)

				// We have an empty cgroup. Remove the cgroup and context store file
				if err := l.netcls.DeleteCgroup(eventInfo.PUID); err != nil {
					zap.L().Warn("Failed to deleted cgroup",
						zap.String("puID", eventInfo.PUID),
						zap.Error(err),
					)
				}

				if err := l.contextStore.Remove(eventInfo.PUID); err != nil {
					zap.L().Warn("Failed to deleted context",
						zap.String("puID", eventInfo.PUID),
						zap.Error(err),
					)
				}

				continue
			}
		}

		reacquired = append(reacquired, eventInfo.PUID)

		// Synchronize
		if storedContext.Tags.IsEmpty() {
			newPUCreated++
		} else {
			if l.config.SyncHandler != nil {
				if err := l.config.SyncHandler.HandleSynchronization(
					contextID,
					events.StateStarted,
					runtimeInfo,
					processor.SynchronizationTypeInitial,
				); err != nil {
					zap.L().Debug("Failed to sync", zap.Error(err))
					syncFailed++
					continue
				}
			}
		}

		if err := l.startInternal(runtimeInfo, eventInfo); err != nil {
			zap.L().Debug("Failed to start", zap.Error(err))
			puStartFailed++
		}
	}

	return nil
}

// generateContextID creates the contextID from the event information
func (l *linuxProcessor) generateContextID(eventInfo *events.EventInfo) (string, error) {

	contextID := eventInfo.PUID
	if eventInfo.Cgroup == "" {
		return contextID, nil
	}

	if !l.regStop.Match([]byte(eventInfo.Cgroup)) {
		return "", fmt.Errorf("invalid pu id: %s", eventInfo.Cgroup)
	}

	contextID = baseName(eventInfo.Cgroup, "/")
	return contextID, nil
}

func (l *linuxProcessor) processLinuxServiceStart(event *events.EventInfo, runtimeInfo *policy.PURuntime) error {

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
			l.netcls.AddProcess(event.PUID, pid) // nolint
			return nil
		}
	}

	//It is okay to launch this so let us create a cgroup for it
	err = l.netcls.Creategroup(event.PUID)
	if err != nil {
		return err
	}

	markval := runtimeInfo.Options().CgroupMark
	if markval == "" {
		if derr := l.netcls.DeleteCgroup(event.PUID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return fmt.Errorf("mark value %s not found", markval)
	}

	mark, _ := strconv.ParseUint(markval, 10, 32)
	err = l.netcls.AssignMark(event.PUID, mark)
	if err != nil {
		if derr := l.netcls.DeleteCgroup(event.PUID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return err
	}

	pid, _ := strconv.Atoi(event.PID)
	err = l.netcls.AddProcess(event.PUID, pid)
	if err != nil {

		if derr := l.netcls.DeleteCgroup(event.PUID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}

		return err
	}

	return nil
}

func (l *linuxProcessor) processHostServiceStart(event *events.EventInfo, runtimeInfo *policy.PURuntime) error {

	if event.NetworkOnlyTraffic {
		return nil
	}

	markval := runtimeInfo.Options().CgroupMark
	mark, _ := strconv.ParseUint(markval, 10, 32)
	hexmark := "0x" + (strconv.FormatUint(mark, 16))

	return ioutil.WriteFile("/sys/fs/cgroup/net_cls,net_prio/net_cls.classid", []byte(hexmark), 0644)
}
