package uidmonitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/monitor/config"
	"github.com/aporeto-inc/trireme-lib/monitor/extractors"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls"
	"github.com/aporeto-inc/trireme-lib/utils/contextstore"
	"github.com/aporeto-inc/trireme-lib/utils/portspec"
)

// uidProcessor captures all the monitor processor information for a UIDLoginPU
// It implements the EventProcessor interface of the rpc monitor
type uidProcessor struct {
	config            *config.ProcessorConfig
	metadataExtractor extractors.EventMetadataExtractor
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
	pidlist            map[int32]bool
	Info               *policy.PURuntime
	publishedContextID string
}

// StoredContext is the information stored to retrieve the context in case of restart.
type StoredContext struct {
	MarkVal   string
	EventInfo *common.EventInfo
	Tags      *policy.TagStore
}

func baseName(name, separator string) string {

	lastseparator := strings.LastIndex(name, separator)
	if len(name) <= lastseparator {
		return ""
	}
	return name[lastseparator+1:]
}

// RemapData Remaps the contextstore data from an old format to the newer format.
func (u *uidProcessor) RemapData(data string, fixedData interface{}) error {
	event := &common.EventInfo{}
	if err := json.Unmarshal([]byte(data), event); err != nil {
		return fmt.Errorf("Received error %s while remapping data", err)
	}
	//Convert the eventInfo data to new format
	for index, s := range event.Services {
		if s.Port != 0 {
			s.Ports = &portspec.PortSpec{
				Min: s.Port,
				Max: s.Port,
			}
		}
		event.Services[index].Ports = s.Ports
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

// Start handles start events
func (u *uidProcessor) Start(ctx context.Context, eventInfo *common.EventInfo) error {

	u.Lock()
	defer u.Unlock()

	puID := eventInfo.PUID
	pids, err := u.putoPidMap.Get(puID)
	var runtimeInfo *policy.PURuntime
	if err != nil {
		runtimeInfo, err = u.metadataExtractor(eventInfo)
		if err != nil {
			return err
		}

		publishedContextID := puID + runtimeInfo.Options().CgroupMark
		// Setup the run time
		if perr := u.config.Policy.HandlePUEvent(ctx, publishedContextID, common.EventStart, runtimeInfo); perr != nil {
			zap.L().Error("Failed to activate process", zap.Error(perr))
			return perr
		}

		if err = u.processLinuxServiceStart(eventInfo, runtimeInfo); err != nil {
			zap.L().Error("processLinuxServiceStart", zap.Error(err))
			return err
		}

		u.config.Collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: puID,
			IPAddress: runtimeInfo.IPAddresses(),
			Tags:      runtimeInfo.Tags(),
			Event:     collector.ContainerStart,
		})
		entry := &puToPidEntry{
			Info:               runtimeInfo,
			publishedContextID: publishedContextID,
			pidlist:            map[int32]bool{},
		}

		entry.pidlist[eventInfo.PID] = true

		if err := u.putoPidMap.Add(puID, entry); err != nil {
			zap.L().Warn("Failed to add puID/PU in the cache",
				zap.Error(err),
				zap.String("puID", puID),
			)
		}

		if err := u.pidToPU.Add(eventInfo.PID, puID); err != nil {
			zap.L().Warn("Failed to add eventInfoID/puID in the cache",
				zap.Error(err),
				zap.String("puID", puID),
			)
		}
		// Store the state in the context store for future access
		return u.contextStore.Store(puID, &StoredContext{
			MarkVal:   runtimeInfo.Options().CgroupMark,
			EventInfo: eventInfo,
			Tags:      runtimeInfo.Tags(),
		})
	}

	pids.(*puToPidEntry).pidlist[eventInfo.PID] = true

	if err := u.pidToPU.Add(eventInfo.PID, eventInfo.PUID); err != nil {
		zap.L().Warn("Failed to add eventInfoPID/eventInfoPUID in the cache",
			zap.Error(err),
			zap.Int32("eventInfo.PID", eventInfo.PID),
			zap.String("eventInfo.PUID", eventInfo.PUID),
		)
	}

	return u.processLinuxServiceStart(eventInfo, pids.(*puToPidEntry).Info)

}

// Stop handles a stop event and destroy as well. Destroy does nothing for the uid monitor
func (u *uidProcessor) Stop(ctx context.Context, eventInfo *common.EventInfo) error {

	puID, err := u.generateContextID(eventInfo)
	if err != nil {
		return err
	}

	if puID == triremeBaseCgroup {
		u.netcls.Deletebasepath(puID)
		return nil
	}
	u.Lock()
	defer u.Unlock()
	//ignore the leading / here this is a special case for stop where i need to do a reverse lookup
	stoppedpid := strings.TrimLeft(puID, "/")
	if puid, err := u.pidToPU.Get(stoppedpid); err == nil {
		puID = puid.(string)
	}

	istoppedpid, _ := strconv.Atoi(stoppedpid)

	var publishedContextID string
	if pidlist, err := u.putoPidMap.Get(puID); err == nil {
		pidCxt := pidlist.(*puToPidEntry)
		publishedContextID = pidCxt.publishedContextID
		// Clean pid from both caches
		delete(pidCxt.pidlist, int32(istoppedpid))

		if err = u.pidToPU.Remove(stoppedpid); err != nil {
			zap.L().Warn("Failed to remove entry in the cache", zap.Error(err), zap.String("stoppedpid", stoppedpid))
		}

		if len(pidlist.(*puToPidEntry).pidlist) != 0 {
			// Only destroy the pid that is being stopped
			return u.netcls.DeleteCgroup(stoppedpid)
		}

		if err = u.config.Policy.HandlePUEvent(ctx, publishedContextID, common.EventStop, nil); err != nil {
			zap.L().Warn("Failed to stop trireme PU ",
				zap.String("puID", puID),
				zap.Error(err),
			)
		}

		if err = u.putoPidMap.Remove(puID); err != nil {
			zap.L().Warn("Failed to remove entry in the cache", zap.Error(err), zap.String("puID", puID))
		}

		if err = u.contextStore.Remove(puID); err != nil {
			zap.L().Error("Failed to clean cache while destroying process",
				zap.String("puID", puID),
				zap.Error(err),
			)
		}

		if err = u.config.Policy.HandlePUEvent(ctx, publishedContextID, common.EventDestroy, nil); err != nil {
			zap.L().Warn("Failed to Destroy clean trireme ",
				zap.String("puID", puID),
				zap.Error(err),
			)
		}

		return u.netcls.DeleteCgroup(stoppedpid)
	}

	return nil

}

// Create handles create events
func (u *uidProcessor) Create(ctx context.Context, eventInfo *common.EventInfo) error {

	return u.config.Policy.HandlePUEvent(ctx, eventInfo.PUID, common.EventCreate, nil)
}

// Destroy handles a destroy event
func (u *uidProcessor) Destroy(ctx context.Context, eventInfo *common.EventInfo) error {
	// Destroy is not used for the UIDMonitor since we will destroy when we get stop
	// This is to try and save some time .Stop/Destroy is two RPC calls.
	// We don't define pause on uid monitor so stop is always followed by destroy
	return nil
}

// Pause handles a pause event
func (u *uidProcessor) Pause(ctx context.Context, eventInfo *common.EventInfo) error {

	puID, err := u.generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("unable to generate context id: %s", err)
	}

	return u.config.Policy.HandlePUEvent(ctx, puID, common.EventPause, nil)
}

// ReSync resyncs with all the existing services that were there before we start
func (u *uidProcessor) ReSync(ctx context.Context, e *common.EventInfo) error {

	deleted := []string{}
	reacquired := []string{}
	marktoPID := map[string][]string{}

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
			zap.L().Debug("UID resync completed",
				zap.Strings("deleted", deleted),
				zap.Strings("reacquired", reacquired),
			)
		} else {
			zap.L().Warn("UID resync completed with failures",
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

	walker, err := u.contextStore.Walk()
	if err != nil {
		return fmt.Errorf("unable to walk context store: %s", err)
	}

	cgroups := cgnetcls.GetCgroupList()

	for _, cgroup := range cgroups {

		pidlist, _ := u.netcls.ListCgroupProcesses(cgroup)
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
		puID := <-walker
		if puID == "" {
			break
		}

		storedContext := &StoredContext{}
		if err := u.contextStore.Retrieve("/"+puID, &storedContext); err != nil {
			retrieveFailed++
			continue
		}
		if storedContext.Tags == nil {
			invalidContextWithNoTags++
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
			if err := u.contextStore.Remove("/" + puID); err != nil {
				zap.L().Warn("Error when removing context in the store", zap.Error(err))
			}
		} else {

			// Synchronize
			if storedContext.Tags.IsEmpty() {
				newPUCreated++
			} else {
				if u.config.Policy != nil {
					if err := u.config.Policy.HandleSynchronization(
						ctx,
						puID,
						common.StateStarted,
						runtimeInfo,
						policy.SynchronizationTypeInitial,
					); err != nil {
						zap.L().Debug("Failed to sync", zap.Error(err))
						syncFailed++
						continue
					}
				}
			}

			for _, pid := range pids {
				iPid, _ := strconv.Atoi(pid)
				eventInfo.PID = int32(iPid)
				if err := u.Start(ctx, eventInfo); err != nil {
					zap.L().Debug("Failed to start", zap.Error(err), zap.Int("eventInfoPID", int(eventInfo.PID)))
					puStartFailed++
				}
			}
		}
	}

	return nil
}

// generateContextID creates the puID from the event information
func (u *uidProcessor) generateContextID(eventInfo *common.EventInfo) (string, error) {

	puID := eventInfo.PUID
	if eventInfo.Cgroup != "" {
		if !u.regStop.Match([]byte(eventInfo.Cgroup)) {
			return "", fmt.Errorf("invalid pu id: %s", eventInfo.Cgroup)
		}
		puID = eventInfo.Cgroup
	}

	puID = baseName(puID, "/")
	return puID, nil
}

func (u *uidProcessor) processLinuxServiceStart(event *common.EventInfo, runtimeInfo *policy.PURuntime) error {

	pidName := strconv.Itoa(int(event.PID))
	if err := u.netcls.Creategroup(pidName); err != nil {
		return err
	}

	markval := runtimeInfo.Options().CgroupMark
	if markval == "" {
		if derr := u.netcls.DeleteCgroup(pidName); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return errors.New("mark value not found")
	}

	mark, err := strconv.ParseUint(markval, 10, 32)
	if err != nil {
		return err
	}

	if err = u.netcls.AssignMark(pidName, mark); err != nil {
		if derr := u.netcls.DeleteCgroup(pidName); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return err
	}

	if err := u.netcls.AddProcess(pidName, int(event.PID)); err != nil {
		if derr := u.netcls.DeleteCgroup(pidName); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return err
	}

	return nil
}
