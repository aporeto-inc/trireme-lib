package linuxmonitor

import (
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/cgnetcls"
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/internal/contextstore"
	"github.com/aporeto-inc/trireme-lib/monitor/impl"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/events"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// linuxProcessor captures all the monitor processor information
// It implements the EventProcessor interface of the rpc monitor
type linuxProcessor struct {
	collector         collector.EventCollector
	puHandler         monitorimpl.ProcessingUnitsHandler
	syncHandler       monitorimpl.SynchronizationHandler
	metadataExtractor events.EventMetadataExtractor
	netcls            cgnetcls.Cgroupnetcls
	contextStore      contextstore.ContextStore
	regStart          *regexp.Regexp
	regStop           *regexp.Regexp
	storePath         string
}

// Create handles create events
func (l *linuxProcessor) Create(eventInfo *events.EventInfo) error {

	if !l.regStart.Match([]byte(eventInfo.PUID)) {
		return fmt.Errorf("Invalid PU ID %s", eventInfo.PUID)
	}

	return l.puHandler.HandlePUEvent(eventInfo.PUID, events.EventCreate)
}

// Start handles start events
func (l *linuxProcessor) Start(eventInfo *events.EventInfo) error {

	// Validate the PUID format

	if !l.regStart.Match([]byte(eventInfo.PUID)) {
		return fmt.Errorf("Invalid PU ID %s", eventInfo.PUID)
	}

	contextID := eventInfo.PUID
	// Extract the metadata
	runtimeInfo, err := l.metadataExtractor(eventInfo)
	if err != nil {
		return err
	}

	// Setup the run time
	if err = l.puHandler.CreatePURuntime(contextID, runtimeInfo); err != nil {
		return err
	}

	defaultIP, _ := runtimeInfo.DefaultIPAddress()
	if perr := l.puHandler.HandlePUEvent(contextID, events.EventStart); perr != nil {
		zap.L().Error("Failed to activate process", zap.Error(perr))
		return perr
	}

	if eventInfo.HostService {
		err = l.processHostServiceStart(eventInfo, runtimeInfo)
	} else {
		err = l.processLinuxServiceStart(eventInfo, runtimeInfo)
	}

	if err != nil {
		return err
	}

	l.collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: defaultIP,
		Tags:      runtimeInfo.Tags(),
		Event:     collector.ContainerStart,
	})

	// Store the state in the context store for future access
	return l.contextStore.Store(contextID, eventInfo)
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

	contextID = contextID[strings.LastIndex(contextID, "/")+1:]
	return l.puHandler.HandlePUEvent(contextID, events.EventStop)
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

	contextID = contextID[strings.LastIndex(contextID, "/")+1:]

	// Send the event upstream
	if err := l.puHandler.HandlePUEvent(contextID, events.EventDestroy); err != nil {
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
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	return l.puHandler.HandlePUEvent(contextID, events.EventPause)
}

// ReSync resyncs with all the existing services that were there before we start
func (l *linuxProcessor) ReSync(e *events.EventInfo) error {

	deleted := []string{}
	reacquired := []string{}

	defer func() {
		if len(deleted) > 0 {
			zap.L().Info("Deleted dead contexts", zap.String("Context List", strings.Join(deleted, ",")))
		}
		if len(reacquired) > 0 {
			zap.L().Info("Reacquired contexts", zap.String("Context List", strings.Join(reacquired, ",")))
		}
	}()

	walker, err := l.contextStore.Walk()
	if err != nil {
		return fmt.Errorf("error in accessing context store")
	}

	for {
		contextID := <-walker
		if contextID == "" {
			break
		}

		eventInfo := events.EventInfo{}
		if err := l.contextStore.Retrieve("/"+contextID, &eventInfo); err != nil {
			continue
		}

		if !eventInfo.HostService {
			processlist, err := cgnetcls.ListCgroupProcesses(eventInfo.PUID)
			if err != nil {
				zap.L().Debug("Removing Context for empty cgroup", zap.String("CONTEXTID", eventInfo.PUID))
				deleted = append(deleted, eventInfo.PUID)
				// The cgroup does not exists - log error and remove context
				if cerr := l.contextStore.Remove(eventInfo.PUID); cerr != nil {
					zap.L().Warn("Failed to remove state from store handler", zap.Error(cerr))
				}
				continue
			}

			if len(processlist) <= 0 {
				// We have an empty cgroup. Remove the cgroup and context store file
				if err := l.netcls.DeleteCgroup(eventInfo.PUID); err != nil {
					zap.L().Warn("Failed to deleted cgroup",
						zap.String("puID", eventInfo.PUID),
						zap.Error(err),
					)
				}
				deleted = append(deleted, eventInfo.PUID)

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

		if err := l.Start(&eventInfo); err != nil {
			zap.L().Error("Failed to start PU ", zap.String("PUID", eventInfo.PUID))
			return fmt.Errorf("error in processing existing data: %s", err.Error())
		}

	}

	return nil
}

// generateContextID creates the contextID from the event information
func (l *linuxProcessor) generateContextID(eventInfo *events.EventInfo) (string, error) {

	contextID := eventInfo.PUID
	if eventInfo.Cgroup != "" {
		if !l.regStop.Match([]byte(eventInfo.Cgroup)) {
			return "", fmt.Errorf("Invalid PUID %s", eventInfo.Cgroup)
		}
		contextID = eventInfo.Cgroup[strings.LastIndex(eventInfo.Cgroup, "/")+1:]
	}
	//contextID = contextID[strings.LastIndex(eventInfo.Cgroup, "/")+1:]
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
		return errors.New("Mark value not found")
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
