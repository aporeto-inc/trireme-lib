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

var ignoreNames = map[string]*struct{}{
	"cgroup.clone_children": nil,
	"cgroup.procs":          nil,
	"net_cls.classid":       nil,
	"net_prio.ifpriomap":    nil,
	"net_prio.prioidx":      nil,
	"notify_on_release":     nil,
	"tasks":                 nil,
}

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

		publishedContextID := puID
		// Setup the run time
		if perr := u.config.Policy.HandlePUEvent(ctx, publishedContextID, common.EventCreate, runtimeInfo); perr != nil {
			zap.L().Error("Failed to create process", zap.Error(perr))
			return perr
		}

		if perr := u.config.Policy.HandlePUEvent(ctx, publishedContextID, common.EventStart, runtimeInfo); perr != nil {
			zap.L().Error("Failed to start process", zap.Error(perr))
			return perr
		}

		if err = u.processLinuxServiceStart(puID, eventInfo, runtimeInfo); err != nil {
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
	}

	pids.(*puToPidEntry).pidlist[eventInfo.PID] = true

	if err := u.pidToPU.Add(eventInfo.PID, eventInfo.PUID); err != nil {
		zap.L().Warn("Failed to add eventInfoPID/eventInfoPUID in the cache",
			zap.Error(err),
			zap.Int32("eventInfo.PID", eventInfo.PID),
			zap.String("eventInfo.PUID", eventInfo.PUID),
		)
	}

	pidPath := puID + "/" + strconv.Itoa(int(eventInfo.PID))

	return u.processLinuxServiceStart(pidPath, eventInfo, pids.(*puToPidEntry).Info)

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
			return u.netcls.DeleteCgroup(puID)
		}

		if err = u.config.Policy.HandlePUEvent(ctx, publishedContextID, common.EventStop, nil); err != nil {
			zap.L().Warn("Failed to stop trireme PU ",
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

		if err = u.putoPidMap.Remove(puID); err != nil {
			zap.L().Warn("Failed to remove entry in the cache", zap.Error(err), zap.String("puID", puID))
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

	uids := u.netcls.ListAllCgroups("")
	for _, uid := range uids {

		if _, ok := ignoreNames[uid]; ok {
			continue
		}

		processesOfUID := u.netcls.ListAllCgroups(uid)
		activePids := []int32{}

		for _, pid := range processesOfUID {
			if _, ok := ignoreNames[pid]; ok {
				continue
			}
			pidlist, _ := u.netcls.ListCgroupProcesses(common.TriremeUIDCgroupPath + pid)
			if len(pidlist) == 0 {
				if err := u.netcls.DeleteCgroup(common.TriremeUIDCgroupPath + pid); err != nil {
					zap.L().Warn("Unable to delete cgroup",
						zap.String("cgroup", uid+"/"+pid),
						zap.Error(err),
					)
				}
				continue
			}

			iPid, _ := strconv.Atoi(pid)
			activePids = append(activePids, int32(iPid))
		}

		if len(activePids) == 0 {
			if err := u.netcls.DeleteCgroup(uid); err != nil {
				zap.L().Warn("Unable to delete cgroup",
					zap.String("cgroup", uid),
					zap.Error(err),
				)
			}
			continue
		}

		event := &common.EventInfo{
			PID:  activePids[0],
			PUID: uid,
		}

		if err := u.Start(ctx, event); err != nil {
			zap.L().Error("Can not synchronize user", zap.String("user", uid))
		}

		if len(activePids) > 1 {
			for _, pid := range activePids {
				event := &common.EventInfo{
					PID:  pid,
					PUID: uid,
				}
				if err := u.Start(ctx, event); err != nil {
					zap.L().Error("Can not synchronize user", zap.String("user", uid))
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

func (u *uidProcessor) processLinuxServiceStart(pidName string, event *common.EventInfo, runtimeInfo *policy.PURuntime) error {

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
