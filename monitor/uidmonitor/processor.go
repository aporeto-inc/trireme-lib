package uidmonitor

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/contextstore"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
)

//UidProcessor -- strcuture to hold provivate info for this processor
type UidProcessor struct {
	collector         collector.EventCollector
	puHandler         monitor.ProcessingUnitsHandler
	metadataExtractor rpcmonitor.RPCMetadataExtractor
	netcls            cgnetcls.Cgroupnetcls
	contextStore      contextstore.ContextStore
}

//NewUidProcessor -- create a new uidprocessor
func NewUidProcessor(collector collector.EventCollector, puHandler monitor.ProcessingUnitsHandler, metadataExtractor rpcmonitor.RPCMetadataExtractor, releasePath string) *UidProcessor {
	return &UidProcessor{
		collector:         collector,
		puHandler:         puHandler,
		metadataExtractor: metadataExtractor,
		netcls:            cgnetcls.NewCgroupNetController(releasePath),
		contextstore:      contextstore.NewContextStore(),
	}
}

//Create -- handles the create event -- we don't expect this event
func (s *UidProcessor) Create(eventInfo *rpcmonitor.EventInfo) error {

	return fmt.Errorf("Received Create :: UidMonitor::Event Not Supported")
}

//Start -- handle the start event
func (s *UidProcessor) Start(eventInfo *rpcmonitor.EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return err
	}

	runtimeInfo, err := s.metadataExtractor(eventInfo)
	if err != nil {
		return err
	}

	if err = s.puHandler.SetPURuntime(contextID, runtimeInfo); err != nil {
		return err
	}

	defaultIP, _ := runtimeInfo.DefaultIPAddress()
	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, monitor.EventStart)

	status := <-errChan
	if status == nil {
		//It is okay to launch this so let us create a cgroup for it
		err = s.netcls.Creategroup(eventInfo.PUID)
		if err != nil {
			return err
		}

		markval, ok := runtimeInfo.Options().Get(cgnetcls.CgroupMarkTag)
		if !ok {
			if derr := s.netcls.DeleteCgroup(eventInfo.PUID); derr != nil {
				zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
			}
			return errors.New("Mark value not found")
		}

		mark, _ := strconv.ParseUint(markval, 10, 32)
		err = s.netcls.AssignMark(eventInfo.PUID, mark)
		if err != nil {
			if derr := s.netcls.DeleteCgroup(eventInfo.PUID); derr != nil {
				zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
			}
			return err
		}

		pid, _ := strconv.Atoi(eventInfo.PID)
		err = s.netcls.AddProcess(eventInfo.PUID, pid)
		if err != nil {

			if derr := s.netcls.DeleteCgroup(eventInfo.PUID); derr != nil {
				zap.L().Warn("Failed to clean cgroup", zap.Error(derr))
			}

			return err

		}

		s.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: defaultIP,
			Tags:      runtimeInfo.Tags(),
			Event:     collector.ContainerStart,
		})
		// Store the state in the context store for future access
		if err := s.contextStore.StoreContext(contextID, eventInfo); err != nil {
			return err
		}
	}

	return status
}

//Stop -- handles the stop event
func (s *UidProcessor) Stop(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	if !strings.HasPrefix(contextID, cgnetcls.TriremeBasePath) || contextID == cgnetcls.TriremeBasePath {
		return nil
	}

	contextID = contextID[strings.LastIndex(contextID, "/"):]

	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, monitor.EventStop)
	status := <-errChan

	return status

}

//Destroy -- handles destroy event
func (s *UidProcessor) Destroy(eventInfo *rpcmonitor.EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	if !strings.HasPrefix(contextID, cgnetcls.TriremeBasePath) || contextID == cgnetcls.TriremeBasePath {
		return nil
	}

	contextID = contextID[strings.LastIndex(contextID, "/"):]

	contextStoreHdl := contextstore.NewContextStore("/var/run/trireme")

	s.netcls.Deletebasepath(contextID)

	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, monitor.EventDestroy)

	<-errChan

	//let us remove the cgroup files now
	if err := s.netcls.DeleteCgroup(contextID); err != nil {
		zap.L().Warn("Failed to clean netcls group",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	if err := contextStoreHdl.RemoveContext(contextID); err != nil {
		zap.L().Warn("Failed to clean cache while destroying process",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	return nil
}

//Pause -- handles the pause event -- does not makes sense for this monitor
func (s *UidProcessor) Pause(eventInfo *rpcmonitor.EventInfo) error {

	return fmt.Errorf("Event Not Supported")
}

// generateContextID creates the contextID from the event information
func generateContextID(eventInfo *rpcmonitor.EventInfo) (string, error) {

	if eventInfo.PUID == "" {
		return "", fmt.Errorf("PUID is empty from eventInfo")
	}

	return eventInfo.PUID, nil
}
