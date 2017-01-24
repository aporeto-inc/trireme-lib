package linuxmonitor

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/collector"
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
}

// NewLinuxProcessor initializes a processor
func NewLinuxProcessor(collector collector.EventCollector, puHandler monitor.ProcessingUnitsHandler, metadataExtractor rpcmonitor.RPCMetadataExtractor) *LinuxProcessor {

	return &LinuxProcessor{
		collector:         collector,
		puHandler:         puHandler,
		metadataExtractor: metadataExtractor,
		netcls:            cgnetcls.NewCgroupNetController(),
	}
}

// Create handles create events
func (s *LinuxProcessor) Create(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	tagsMap := policy.NewTagsMap(eventInfo.Tags)
	s.collector.CollectContainerEvent(contextID, "localhost", tagsMap, collector.ContainerCreate)

	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, monitor.EventCreate)
	return <-errChan
}

// Start handles start events
func (s *LinuxProcessor) Start(eventInfo *rpcmonitor.EventInfo) error {

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
			log.WithFields(log.Fields{
				"package": "rpcMonitor",
				"error":   err.Error(),
			}).Info("Error Creating cgroup")
			return err
		}

		markval, ok := runtimeInfo.Options().Get(cgnetcls.CgroupMarkTag)
		if !ok {
			s.netcls.DeleteCgroup(eventInfo.PUID)
			log.WithFields(log.Fields{
				"package": "rpcmonitor",
				"PUID":    eventInfo.PUID,
			}).Error("Mark value not found")
			return errors.New("Mark value not found")
		}

		mark, _ := strconv.ParseUint(markval, 10, 32)
		err = s.netcls.AssignMark(eventInfo.PUID, mark)
		if err != nil {
			s.netcls.DeleteCgroup(eventInfo.PUID)
			log.WithFields(log.Fields{
				"package": "rpcMonitor",
				"error":   err.Error(),
			}).Info("Error assigning mark value")
			return err
		}

		pid, _ := strconv.Atoi(eventInfo.PID)
		err = s.netcls.AddProcess(eventInfo.PUID, pid)
		if err != nil {
			s.netcls.DeleteCgroup(eventInfo.PUID)
			log.WithFields(log.Fields{
				"package": "rpcMonitor",
				"error":   err.Error(),
			}).Info("Error adding process")
			return err

		}
		s.collector.CollectContainerEvent(contextID, defaultIP, runtimeInfo.Tags(), collector.ContainerStart)
	}

	// Store the state in the context store for future access
	contextstore.NewContextStore().StoreContext(contextID, eventInfo)
	return status
}

// Stop handles a stop event
func (s *LinuxProcessor) Stop(eventInfo *rpcmonitor.EventInfo) error {

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

// Destroy handles a destroy event
func (s *LinuxProcessor) Destroy(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	if !strings.HasPrefix(contextID, cgnetcls.TriremeBasePath) || contextID == cgnetcls.TriremeBasePath {
		return nil
	}

	contextID = contextID[strings.LastIndex(contextID, "/"):]

	contextStoreHdl := contextstore.NewContextStore()

	s.netcls.Deletebasepath(contextID)

	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, monitor.EventDestroy)

	<-errChan

	//let us remove the cgroup files now
	s.netcls.DeleteCgroup(contextID)
	contextStoreHdl.RemoveContext(contextID)

	return nil
}

// Pause handles a pause event
func (s *LinuxProcessor) Pause(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	errChan := s.puHandler.HandlePUEvent(contextID, monitor.EventPause)
	return <-errChan
}

// generateContextID creates the contextID from the event information
func generateContextID(eventInfo *rpcmonitor.EventInfo) (string, error) {

	if eventInfo.PUID == "" {
		return "", fmt.Errorf("PUID is empty from eventInfo")
	}

	return eventInfo.PUID, nil
}
