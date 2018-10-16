package uidmonitor

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.aporeto.io/trireme-lib/utils/cgnetcls"
	"go.uber.org/zap"
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
	regStart          *regexp.Regexp
	regStop           *regexp.Regexp
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

// Start handles start events
func (u *uidProcessor) Start(ctx context.Context, eventInfo *common.EventInfo) error {

	return u.createAndStart(ctx, eventInfo, false)
}

// Stop handles a stop event and destroy as well. Destroy does nothing for the uid monitor
func (u *uidProcessor) Stop(ctx context.Context, eventInfo *common.EventInfo) error {

	puID := eventInfo.PUID

	if puID == triremeBaseCgroup {
		u.netcls.Deletebasepath(puID)
		return nil
	}

	u.Lock()
	defer u.Unlock()

	// Take the PID part of the user/pid PUID
	var pid string
	userID := eventInfo.PUID
	parts := strings.SplitN(puID, "/", 2)
	if len(parts) == 2 {
		userID = parts[0]
		pid = parts[1]
	}

	if len(pid) > 0 {
		// Delete the cgroup for that pid
		if err := u.netcls.DeleteCgroup(puID); err != nil {
			return err
		}

		if pidlist, err := u.putoPidMap.Get(userID); err == nil {
			pidCxt := pidlist.(*puToPidEntry)

			iPid, err := strconv.Atoi(pid)
			if err != nil {
				return err
			}

			// Clean pid from both caches
			delete(pidCxt.pidlist, int32(iPid))

			if err = u.pidToPU.Remove(int32(iPid)); err != nil {
				zap.L().Warn("Failed to remove entry in the cache", zap.Error(err), zap.String("stopped pid", pid))
			}
		}
		return nil
	}

	runtime := policy.NewPURuntimeWithDefaults()
	runtime.SetPUType(common.UIDLoginPU)

	// Since all the PIDs of the user are gone, we can delete the user context.
	if err := u.config.Policy.HandlePUEvent(ctx, userID, common.EventStop, runtime); err != nil {
		zap.L().Warn("Failed to stop trireme PU ",
			zap.String("puID", puID),
			zap.Error(err),
		)
	}

	if err := u.config.Policy.HandlePUEvent(ctx, userID, common.EventDestroy, runtime); err != nil {
		zap.L().Warn("Failed to Destroy clean trireme ",
			zap.String("puID", puID),
			zap.Error(err),
		)
	}

	if err := u.putoPidMap.Remove(userID); err != nil {
		zap.L().Warn("Failed to remove entry in the cache", zap.Error(err), zap.String("puID", puID))
	}

	return u.netcls.DeleteCgroup(strings.TrimRight(userID, "/"))
}

// Create handles create events
func (u *uidProcessor) Create(ctx context.Context, eventInfo *common.EventInfo) error {
	return nil
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

	return u.config.Policy.HandlePUEvent(ctx, eventInfo.PUID, common.EventPause, nil)
}

// Resync resyncs with all the existing services that were there before we start
func (u *uidProcessor) Resync(ctx context.Context, e *common.EventInfo) error {

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

			cgroupPath := uid + "/" + pid
			pidlist, _ := u.netcls.ListCgroupProcesses(cgroupPath)
			if len(pidlist) == 0 {
				if err := u.netcls.DeleteCgroup(cgroupPath); err != nil {
					zap.L().Warn("Unable to delete cgroup",
						zap.String("cgroup", cgroupPath),
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
			PID:    activePids[0],
			PUID:   uid,
			PUType: common.UIDLoginPU,
		}

		if err := u.createAndStart(ctx, event, true); err != nil {
			zap.L().Error("Can not synchronize user", zap.String("user", uid))
		}

		for i := 1; i < len(activePids); i++ {
			event := &common.EventInfo{
				PID:    activePids[i],
				PUID:   uid,
				PUType: common.UIDLoginPU,
			}
			if err := u.createAndStart(ctx, event, true); err != nil {
				zap.L().Error("Can not synchronize user", zap.String("user", uid))
			}
		}
	}

	return nil
}

func (u *uidProcessor) createAndStart(ctx context.Context, eventInfo *common.EventInfo, startOnly bool) error {

	u.Lock()
	defer u.Unlock()

	if eventInfo.Name == "" {
		eventInfo.Name = eventInfo.PUID
	}

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
		if !startOnly {
			if perr := u.config.Policy.HandlePUEvent(ctx, publishedContextID, common.EventCreate, runtimeInfo); perr != nil {
				zap.L().Error("Failed to create process", zap.Error(perr))
				return perr
			}
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

		if err := u.putoPidMap.Add(puID, entry); err != nil {
			zap.L().Warn("Failed to add puID/PU in the cache",
				zap.Error(err),
				zap.String("puID", puID),
			)
		}

		pids = entry
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

func (u *uidProcessor) processLinuxServiceStart(pidName string, event *common.EventInfo, runtimeInfo *policy.PURuntime) error {

	if err := u.netcls.Creategroup(pidName); err != nil {
		zap.L().Error("Failed to create cgroup for the user", zap.String("user", pidName), zap.Error(err))
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
