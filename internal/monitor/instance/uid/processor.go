package uidmonitor

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/rpc/events"
	"github.com/aporeto-inc/trireme-lib/rpc/processor"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls"
	"github.com/aporeto-inc/trireme-lib/utils/contextstore"
)

// uidProcessor captures all the monitor processor information for a UIDLoginPU
// It implements the EventProcessor interface of the rpc monitor
type uidProcessor struct {
	config            *processor.Config
	metadataExtractor events.EventMetadataExtractor
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

// puToPidEntry represents an entry to puToPidMap
type puToPidEntry struct {
	pidlist            map[string]bool
	Info               *policy.PURuntime
	publishedContextID string
}

// StoredContext is the information stored to retrieve the context in case of restart.
type StoredContext struct {
	MarkVal   string
	EventInfo *events.EventInfo
	Tags      *policy.TagStore
}

func baseName(name, separator string) string {

	lastseparator := strings.LastIndex(name, separator)
	if len(name) <= lastseparator {
		return ""
	}
	return name[lastseparator+1:]
}

// Start handles start events
func (u *uidProcessor) Start(eventInfo *events.EventInfo) error {

	u.Lock()
	defer u.Unlock()

	contextID := eventInfo.PUID
	pids, err := u.putoPidMap.Get(contextID)
	var runtimeInfo *policy.PURuntime
	if err != nil {
		runtimeInfo, err = u.metadataExtractor(eventInfo)
		if err != nil {
			return err
		}

		publishedContextID := contextID + runtimeInfo.Options().CgroupMark
		// Setup the run time
		if err = u.config.PUHandler.CreatePURuntime(publishedContextID, runtimeInfo); err != nil {
			return err
		}

		defaultIP, _ := runtimeInfo.DefaultIPAddress()
		if perr := u.config.PUHandler.HandlePUEvent(publishedContextID, events.EventStart); perr != nil {
			zap.L().Error("Failed to activate process", zap.Error(perr))
			return perr
		}

		if err = u.processLinuxServiceStart(eventInfo, runtimeInfo); err != nil {
			zap.L().Error("processLinuxServiceStart", zap.Error(err))
			return err
		}

		u.config.Collector.CollectContainerEvent(&collector.ContainerRecord{
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

		if err := u.putoPidMap.Add(contextID, entry); err != nil {
			zap.L().Warn("Failed to add contextID/PU in the cache",
				zap.Error(err),
				zap.String("contextID", contextID),
			)
		}

		if err := u.pidToPU.Add(eventInfo.PID, contextID); err != nil {
			zap.L().Warn("Failed to add eventInfoID/contextID in the cache",
				zap.Error(err),
				zap.String("contextID", contextID),
			)
		}
		// Store the state in the context store for future access
		return u.contextStore.Store(contextID, &StoredContext{
			MarkVal:   runtimeInfo.Options().CgroupMark,
			EventInfo: eventInfo,
			Tags:      runtimeInfo.Tags(),
		})
	}

	pids.(*puToPidEntry).pidlist[eventInfo.PID] = true

	if err := u.pidToPU.Add(eventInfo.PID, eventInfo.PUID); err != nil {
		zap.L().Warn("Failed to add eventInfoPID/eventInfoPUID in the cache",
			zap.Error(err),
			zap.String("eventInfo.PID", eventInfo.PID),
			zap.String("eventInfo.PUID", eventInfo.PUID),
		)
	}

	return u.processLinuxServiceStart(eventInfo, pids.(*puToPidEntry).Info)

}

// Stop handles a stop event and destroy as well. Destroy does nothing for the uid monitor
func (u *uidProcessor) Stop(eventInfo *events.EventInfo) error {

	contextID, err := u.generateContextID(eventInfo)
	if err != nil {
		return err
	}

	if contextID == triremeBaseCgroup {
		u.netcls.Deletebasepath(contextID)
		return nil
	}
	u.Lock()
	defer u.Unlock()
	//ignore the leading / here this is a special case for stop where i need to do a reverse lookup
	stoppedpid := strings.TrimLeft(contextID, "/")
	if puid, err := u.pidToPU.Get(stoppedpid); err == nil {
		contextID = puid.(string)
	}

	var publishedContextID string
	if pidlist, err := u.putoPidMap.Get(contextID); err == nil {
		ctx := pidlist.(*puToPidEntry)
		publishedContextID = ctx.publishedContextID
		// Clean pid from both caches
		delete(ctx.pidlist, stoppedpid)

		if err = u.pidToPU.Remove(stoppedpid); err != nil {
			zap.L().Warn("Failed to remove entry in the cache", zap.Error(err), zap.String("stoppedpid", stoppedpid))
		}

		if len(pidlist.(*puToPidEntry).pidlist) != 0 {
			// Only destroy the pid that is being stopped
			return u.netcls.DeleteCgroup(stoppedpid)
		}

		if err = u.config.PUHandler.HandlePUEvent(publishedContextID, events.EventStop); err != nil {
			zap.L().Warn("Failed to stop trireme PU ",
				zap.String("contextID", contextID),
				zap.Error(err),
			)
		}

		if err = u.putoPidMap.Remove(contextID); err != nil {
			zap.L().Warn("Failed to remove entry in the cache", zap.Error(err), zap.String("contextID", contextID))
		}

		if err = u.contextStore.Remove(contextID); err != nil {
			zap.L().Error("Failed to clean cache while destroying process",
				zap.String("contextID", contextID),
				zap.Error(err),
			)
		}

		if err = u.config.PUHandler.HandlePUEvent(publishedContextID, events.EventDestroy); err != nil {
			zap.L().Warn("Failed to Destroy clean trireme ",
				zap.String("contextID", contextID),
				zap.Error(err),
			)
		}

		return u.netcls.DeleteCgroup(stoppedpid)
	}

	return nil

}

// Create handles create events
func (u *uidProcessor) Create(eventInfo *events.EventInfo) error {

	return u.config.PUHandler.HandlePUEvent(eventInfo.PUID, events.EventCreate)
}

// Destroy handles a destroy event
func (u *uidProcessor) Destroy(eventInfo *events.EventInfo) error {
	// Destroy is not used for the UIDMonitor since we will destroy when we get stop
	// This is to try and save some time .Stop/Destroy is two RPC calls.
	// We don't define pause on uid monitor so stop is always followed by destroy
	return nil
}

// Pause handles a pause event
func (u *uidProcessor) Pause(eventInfo *events.EventInfo) error {

	contextID, err := u.generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("unable to generate context id: %s", err)
	}

	return u.config.PUHandler.HandlePUEvent(contextID, events.EventPause)
}

// ReSync resyncs with all the existing services that were there before we start
func (u *uidProcessor) ReSync(e *events.EventInfo) error {

	deleted := []string{}
	reacquired := []string{}
	marktoPID := map[string][]string{}

	retrieveFailed := 0
	metadataExtractionFailed := 0
	syncFailed := 0
	puStartFailed := 0

	defer func() {
		if retrieveFailed == 0 &&
			metadataExtractionFailed == 0 &&
			syncFailed == 0 &&
			puStartFailed == 0 {
			zap.L().Info("UID resync completed",
				zap.String("Deleted Contexts", strings.Join(deleted, ",")),
				zap.String("Reacquired Contexts", strings.Join(reacquired, ",")),
			)
		} else {
			zap.L().Info("UID resync completed with failures",
				zap.String("Deleted Contexts", strings.Join(deleted, ",")),
				zap.String("Reacquired Contexts", strings.Join(reacquired, ",")),
				zap.Int("Retrieve Failed", retrieveFailed),
				zap.Int("Metadata Extraction Failed", metadataExtractionFailed),
				zap.Int("Sync Failed", syncFailed),
				zap.Int("puStart Failed", puStartFailed),
			)
		}
	}()

	walker, err := u.contextStore.Walk()
	if err != nil {
		return fmt.Errorf("unable to walk context store: %s", err)
	}

	cgroups := cgnetcls.GetCgroupList()

	for _, cgroup := range cgroups {

		pidlist, _ := cgnetcls.ListCgroupProcesses(cgroup)
		if len(pidlist) == 0 {
			if err := u.netcls.DeleteCgroup(cgroup); err != nil {
				zap.L().Warn("Unable to delete cgroup",
					zap.String("cgroup", cgroup),
					zap.Error(err),
				)
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

		storedContext := &StoredContext{}
		if err := u.contextStore.Retrieve("/"+contextID, &storedContext); err != nil {
			retrieveFailed++
			continue
		}

		// Add specific tags
		eventInfo := storedContext.EventInfo
		for _, t := range u.config.MergeTags {
			if val, ok := storedContext.Tags.Get(t); ok {
				eventInfo.Tags = append(eventInfo.Tags, t+"="+val)
			}
		}
		runtimeInfo, err := u.metadataExtractor(eventInfo)
		if err != nil {
			metadataExtractionFailed++
			continue
		}
		t := runtimeInfo.Tags()
		if t != nil {
			t.Merge(storedContext.Tags)
			runtimeInfo.SetTags(t)
		}

		mark := storedContext.MarkVal
		if pids, ok := marktoPID[mark]; !ok {
			// No pids with stored mark destroy the context record and go to next context
			if err := u.contextStore.Remove("/" + contextID); err != nil {
				zap.L().Warn("Error when removing context in the store", zap.Error(err))
			}
		} else {

			// Synchronize
			if u.config.SyncHandler != nil {
				if err := u.config.SyncHandler.HandleSynchronization(
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

			for _, pid := range pids {
				eventInfo.PID = pid
				if err := u.Start(eventInfo); err != nil {
					zap.L().Debug("Failed to start", zap.Error(err), zap.String("eventInfoPID", eventInfo.PID))
					puStartFailed++
				}
			}
		}
	}

	return nil
}

// generateContextID creates the contextID from the event information
func (u *uidProcessor) generateContextID(eventInfo *events.EventInfo) (string, error) {

	contextID := eventInfo.PUID
	if eventInfo.Cgroup != "" {
		if !u.regStop.Match([]byte(eventInfo.Cgroup)) {
			return "", fmt.Errorf("invalid pu id: %s", eventInfo.Cgroup)
		}
		contextID = eventInfo.Cgroup
	}

	contextID = baseName(contextID, "/")
	return contextID, nil
}

func (u *uidProcessor) processLinuxServiceStart(event *events.EventInfo, runtimeInfo *policy.PURuntime) error {

	if err := u.netcls.Creategroup(event.PID); err != nil {
		return err
	}

	markval := runtimeInfo.Options().CgroupMark
	if markval == "" {
		if derr := u.netcls.DeleteCgroup(event.PID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return errors.New("mark value not found")
	}

	mark, err := strconv.ParseUint(markval, 10, 32)
	if err != nil {
		return err
	}

	if err = u.netcls.AssignMark(event.PID, mark); err != nil {
		if derr := u.netcls.DeleteCgroup(event.PID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return err
	}

	pid, err := strconv.Atoi(event.PID)
	if err != nil {
		return err
	}

	if err := u.netcls.AddProcess(event.PID, pid); err != nil {
		if derr := u.netcls.DeleteCgroup(event.PID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return err
	}

	return nil
}
