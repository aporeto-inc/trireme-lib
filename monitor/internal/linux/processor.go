package linuxmonitor

import (
	"context"
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.aporeto.io/trireme-lib/buildflags"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"
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

// linuxProcessor captures all the monitor processor information
// It implements the EventProcessor interface of the rpc monitor
type linuxProcessor struct {
	host              bool
	ssh               bool
	config            *config.ProcessorConfig
	metadataExtractor extractors.EventMetadataExtractor
	netcls            cgnetcls.Cgroupnetcls
	regStart          *regexp.Regexp
	regStop           *regexp.Regexp
	sync.Mutex
}

func baseName(name, separator string) string {

	lastseparator := strings.LastIndex(name, separator)
	if len(name) <= lastseparator {
		return ""
	}
	return name[lastseparator+1:]
}

// Create handles create events
func (l *linuxProcessor) Create(ctx context.Context, eventInfo *common.EventInfo) error {
	// This should never be called for Linux Processes
	return fmt.Errorf("Use start directly for Linux processes. Create not supported")
}

// Start handles start events
func (l *linuxProcessor) Start(ctx context.Context, eventInfo *common.EventInfo) error {

	// Validate the PUID format. Additional validations TODO
	if !l.regStart.Match([]byte(eventInfo.PUID)) {
		return fmt.Errorf("invalid pu id: %s", eventInfo.PUID)
	}

	// Normalize to a nativeID context. This will become key for any recoveries
	// and it's an one way function.
	nativeID, err := l.generateContextID(eventInfo)
	if err != nil {
		return err
	}

	processes, err := l.netcls.ListCgroupProcesses(nativeID)
	if err == nil && len(processes) != 0 {
		//This PU already exists we are getting a duplicate event
		zap.L().Debug("Duplicate start event for the same PU", zap.String("PUID", nativeID))
		if err = l.netcls.AddProcess(nativeID, int(eventInfo.PID)); err != nil {
			if derr := l.netcls.DeleteCgroup(nativeID); derr != nil {
				zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
			}
			return err
		}
		return nil
	}

	// Extract the metadata and create the runtime
	runtime, err := l.metadataExtractor(eventInfo)
	if err != nil {
		return err
	}

	// We need to send a create event to the policy engine.
	if err = l.config.Policy.HandlePUEvent(ctx, nativeID, common.EventCreate, runtime); err != nil {
		return fmt.Errorf("Unable to create PU: %s", err)
	}

	// We can now send a start event to the policy engine
	if err = l.config.Policy.HandlePUEvent(ctx, nativeID, common.EventStart, runtime); err != nil {
		return fmt.Errorf("Unable to start PU: %s", err)
	}

	l.Lock()
	// We can now program cgroups and everything else.
	if eventInfo.HostService {
		err = l.processHostServiceStart(eventInfo, runtime)
	} else {
		err = l.processLinuxServiceStart(nativeID, eventInfo, runtime)
	}
	l.Unlock()
	if err != nil {
		return fmt.Errorf("Failed to program cgroups: %s", err)
	}

	// Send the event to the collector.
	l.config.Collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: eventInfo.PUID,
		IPAddress: runtime.IPAddresses(),
		Tags:      runtime.Tags(),
		Event:     collector.ContainerStart,
	})

	return nil
}

// Stop handles a stop event
func (l *linuxProcessor) Stop(ctx context.Context, event *common.EventInfo) error {

	puID, err := l.generateContextID(event)
	if err != nil {
		return err
	}

	processes, err := l.netcls.ListCgroupProcesses(puID)
	if err == nil && len(processes) != 0 {
		zap.L().Debug("Received Bogus Stop", zap.Int("Num Processes", len(processes)), zap.Error(err))
		return nil
	}

	if puID == "/trireme" {
		return nil
	}

	runtime := policy.NewPURuntimeWithDefaults()
	runtime.SetPUType(event.PUType)

	return l.config.Policy.HandlePUEvent(ctx, puID, common.EventStop, runtime)
}

// Destroy handles a destroy event
func (l *linuxProcessor) Destroy(ctx context.Context, eventInfo *common.EventInfo) error {

	puID, err := l.generateContextID(eventInfo)
	if err != nil {
		return err
	}

	if puID == "/trireme" {
		puID = strings.TrimLeft(puID, "/")
		l.netcls.Deletebasepath(puID)
		return nil
	}

	runtime := policy.NewPURuntimeWithDefaults()
	runtime.SetPUType(eventInfo.PUType)

	// Send the event upstream
	if err := l.config.Policy.HandlePUEvent(ctx, puID, common.EventDestroy, runtime); err != nil {
		zap.L().Warn("Unable to clean trireme ",
			zap.String("puID", puID),
			zap.Error(err),
		)
	}

	l.Lock()
	defer l.Unlock()

	if eventInfo.HostService {
		// For network only pus, we do not program cgroups and hence should not clean it.
		// Cleaning this could result in removal of root cgroup that was configured for
		// true host mode pu.
		if eventInfo.NetworkOnlyTraffic {
			return nil
		}

		if err := ioutil.WriteFile("/sys/fs/cgroup/net_cls,net_prio/net_cls.classid", []byte("0"), 0644); err != nil {
			return fmt.Errorf("unable to write to net_cls.classid file for new cgroup: %s", err)
		}
	}

	puID = baseName(puID, "/")

	//let us remove the cgroup files now
	if err := l.netcls.DeleteCgroup(puID); err != nil {
		zap.L().Warn("Failed to clean netcls group",
			zap.String("puID", puID),
			zap.Error(err),
		)
	}

	return nil
}

// Pause handles a pause event
func (l *linuxProcessor) Pause(ctx context.Context, eventInfo *common.EventInfo) error {

	puID, err := l.generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("unable to generate context id: %s", err)
	}

	return l.config.Policy.HandlePUEvent(ctx, puID, common.EventPause, nil)
}

func (l *linuxProcessor) resyncHostService(ctx context.Context, e *common.EventInfo) error {

	runtime, err := l.metadataExtractor(e)
	if err != nil {
		return err
	}

	nativeID, err := l.generateContextID(e)
	if err != nil {
		return err
	}

	if err = l.config.Policy.HandlePUEvent(ctx, nativeID, common.EventStart, runtime); err != nil {
		return fmt.Errorf("Unable to start PU: %s", err)
	}

	return l.processHostServiceStart(e, runtime)
}

// Resync resyncs with all the existing services that were there before we start
func (l *linuxProcessor) Resync(ctx context.Context, e *common.EventInfo) error {

	if e != nil {
		// If its a host service then use pu from eventInfo
		// The code block below assumes that pu is already created
		if e.HostService {
			return l.resyncHostService(ctx, e)
		}
	}

	cgroups := l.netcls.ListAllCgroups("")
	for _, cgroup := range cgroups {

		if _, ok := ignoreNames[cgroup]; ok {
			continue
		}

		isSSHPU := strings.Contains(cgroup, "ssh")
		if l.ssh != isSSHPU {
			continue
		}

		// List all the cgroup processes. If its empty, we can remove it.
		procs, err := l.netcls.ListCgroupProcesses(cgroup)
		if err != nil {
			continue
		}

		// All processes in cgroup have died. Let's clean up.
		if len(procs) == 0 {
			if err := l.netcls.DeleteCgroup(cgroup); err != nil {
				zap.L().Warn("Failed to deleted cgroup",
					zap.String("cgroup", cgroup),
					zap.Error(err),
				)
			}
			continue
		}

		runtime := policy.NewPURuntimeWithDefaults()
		puType := common.LinuxProcessPU
		if l.ssh && isSSHPU {
			puType = common.SSHSessionPU
		}
		runtime.SetPUType(puType)
		runtime.SetOptions(policy.OptionsType{
			CgroupMark: strconv.FormatUint(cgnetcls.MarkVal(), 10),
			CgroupName: cgroup,
		})

		// Processes are still alive. We should enforce policy.
		if err := l.config.Policy.HandlePUEvent(ctx, cgroup, common.EventStart, runtime); err != nil {
			zap.L().Error("Failed to restart cgroup control", zap.String("cgroup ID", cgroup), zap.Error(err))
		}

		if err := l.processLinuxServiceStart(cgroup, nil, runtime); err != nil {
			return err
		}
	}
	return nil
}

// generateContextID creates the puID from the event information
func (l *linuxProcessor) generateContextID(eventInfo *common.EventInfo) (string, error) {

	puID := eventInfo.PUID
	if eventInfo.Cgroup == "" {
		return puID, nil
	}

	if !l.regStop.Match([]byte(eventInfo.Cgroup)) {
		return "", fmt.Errorf("invalid pu id: %s", eventInfo.Cgroup)
	}

	puID = baseName(eventInfo.Cgroup, "/")

	if eventInfo.PUType == common.SSHSessionPU {
		return "ssh-" + puID, nil
	}

	return puID, nil
}

func (l *linuxProcessor) processLinuxServiceStart(nativeID string, event *common.EventInfo, runtimeInfo *policy.PURuntime) error {

	//It is okay to launch this so let us create a cgroup for it
	err := l.netcls.Creategroup(nativeID)
	if err != nil {
		return err
	}

	markval := runtimeInfo.Options().CgroupMark
	if markval == "" {
		if derr := l.netcls.DeleteCgroup(nativeID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return fmt.Errorf("mark value %s not found", markval)
	}

	mark, _ := strconv.ParseUint(markval, 10, 32)
	err = l.netcls.AssignMark(nativeID, mark)
	if err != nil {
		if derr := l.netcls.DeleteCgroup(nativeID); derr != nil {
			zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
		}
		return err
	}

	if event != nil {
		err = l.netcls.AddProcess(nativeID, int(event.PID))
		if err != nil {
			if derr := l.netcls.DeleteCgroup(nativeID); derr != nil {
				zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
			}
			return err
		}
	}

	return nil
}

func (l *linuxProcessor) processHostServiceStart(event *common.EventInfo, runtimeInfo *policy.PURuntime) error {

	if event.NetworkOnlyTraffic || buildflags.IsLegacyKernel() {
		return nil
	}

	markval := runtimeInfo.Options().CgroupMark
	mark, _ := strconv.ParseUint(markval, 10, 32)
	hexmark := "0x" + (strconv.FormatUint(mark, 16))

	return ioutil.WriteFile("/sys/fs/cgroup/net_cls,net_prio/net_cls.classid", []byte(hexmark), 0644)
}
