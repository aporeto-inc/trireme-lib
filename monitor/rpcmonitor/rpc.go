package rpcmonitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/contextstore"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/policy"
)

// RPCMetadataExtractor is a function used to extract a *policy.PURuntime from a given
// EventInfo.
type RPCMetadataExtractor func(*EventInfo) (*policy.PURuntime, error)

func defaultRPCMetadataExtractor(event *EventInfo) (*policy.PURuntime, error) {

	if event.Name == "" {
		return nil, fmt.Errorf("EventInfo PU Name is empty")
	}

	if event.PID == "" {
		return nil, fmt.Errorf("EventInfo PID is empty")
	}

	if event.PUID == "" {
		return nil, fmt.Errorf("EventInfo PUID is empty")
	}

	runtimeTags := policy.NewTagsMap(event.Tags)
	runtimeIps := policy.NewIPMap(event.IPs)
	runtimePID, err := strconv.Atoi(event.PID)
	if err != nil {
		return nil, fmt.Errorf("PID is invalid: %s", err)
	}

	return policy.NewPURuntime(event.Name, runtimePID, runtimeTags, runtimeIps, policy.ContainerPU, nil), nil
}

// A RPCEventHandler is type of docker event handler functions.
type RPCEventHandler func(*EventInfo) error

// rpcMonitor implements the RPC connection
type rpcMonitor struct {
	rpcAddress    string
	rpcServer     *rpc.Server
	monitorServer *Server
	listensock    net.Listener
}

// Server represents the Monitor RPC Server implementation
type Server struct {
	handlers          map[monitor.Event]RPCEventHandler
	metadataExtractor RPCMetadataExtractor
	collector         collector.EventCollector
	puHandler         monitor.ProcessingUnitsHandler
	netcls            cgnetcls.Cgroupnetcls
	contextstore      contextstore.ContextStore
}

// NewRPCMonitor returns a fully initialized RPC Based monitor.
func NewRPCMonitor(
	rpcAddress string,
	metadataExtractor RPCMetadataExtractor,
	puHandler monitor.ProcessingUnitsHandler,
	collector collector.EventCollector,
	netcls cgnetcls.Cgroupnetcls,
	contextstorehdl contextstore.ContextStore) (monitor.Monitor, error) {

	if rpcAddress == "" {
		return nil, fmt.Errorf("RPC endpoint address invalid")
	}

	if puHandler == nil {
		return nil, fmt.Errorf("PU Handler required")
	}

	monitorServer := &Server{
		collector:         collector,
		puHandler:         puHandler,
		metadataExtractor: metadataExtractor,
		handlers:          map[monitor.Event]RPCEventHandler{},
		netcls:            netcls,
		contextstore:      contextstorehdl,
	}

	if metadataExtractor == nil {
		monitorServer.metadataExtractor = defaultRPCMetadataExtractor
	}

	monitorServer.addHandler(monitor.EventStart, monitorServer.handleStartEvent)
	monitorServer.addHandler(monitor.EventStop, monitorServer.handleStopEvent)
	monitorServer.addHandler(monitor.EventCreate, monitorServer.handleCreateEvent)
	monitorServer.addHandler(monitor.EventDestroy, monitorServer.handleDestroyEvent)
	monitorServer.addHandler(monitor.EventPause, monitorServer.handlePauseEvent)

	r := &rpcMonitor{
		rpcAddress:    rpcAddress,
		monitorServer: monitorServer,
	}

	// Registering the monitorRPCServer as an RPC Server.
	r.rpcServer = rpc.NewServer()
	err := r.rpcServer.Register(r.monitorServer)
	if err != nil {
		log.Fatalf("Format of service MonitorServer isn't correct. %s", err)
	}

	return r, nil
}

// reSync resyncs with all the existing services that were there before we start
func (r *rpcMonitor) reSync() error {

	walker, err := r.monitorServer.contextstore.WalkStore()
	if err != nil {
		return fmt.Errorf("error in accessing context store")
	}

	for {
		contextID := <-walker
		if contextID == "" {
			break
		}

		data, err := r.monitorServer.contextstore.GetContextInfo("/" + contextID)
		if err == nil && data != nil {

			var eventInfo EventInfo

			if err := json.Unmarshal(data.([]byte), &eventInfo); err != nil {
				return fmt.Errorf("error in umarshalling date")
			}

			if err := r.monitorServer.handleStartEvent(&eventInfo); err != nil {
				return fmt.Errorf("error in processing existing data")
			}
		}
	}

	return nil
}

// processRequests processes the RPC requests
func (r *rpcMonitor) processRequests() {
	for {
		conn, err := r.listensock.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "closed") {
				log.WithFields(log.Fields{
					"package": "monitor",
					"error":   err.Error(),
				}).Error("Error while handling RPC event")
			}

			break
		}

		r.rpcServer.ServeCodec(jsonrpc.NewServerCodec(conn))
	}
}

// Start starts the RPC monitoring.
func (r *rpcMonitor) Start() error {

	var err error

	log.WithFields(log.Fields{"package": "rpcmonitor",
		"message:": "Starting rcp monitor",
		"socket":   r.rpcAddress,
	}).Info("Starting RPC monitor")

	// Check if we had running units when we last died
	if err = r.reSync(); err != nil {
		log.WithFields(log.Fields{
			"package":  "rpcmonitor",
			"error":    err.Error(),
			"message:": "Unable to resync existing services",
		}).Error("Failed to resync existing services")
	}

	if r.listensock, err = net.Listen("unix", r.rpcAddress); err != nil {
		log.WithFields(log.Fields{"package": "rpcmonitor",
			"error":    err.Error(),
			"message:": "Starting",
		}).Info("Failed RPC monitor")
		return fmt.Errorf("couldn't create binding: %s", err)
	}

	if err = os.Chmod(r.rpcAddress, 0766); err != nil {
		log.WithFields(log.Fields{"package": "rpcmonitor",
			"error":    err.Error(),
			"message:": "Failed to adjust permissions on rpc socket path",
		}).Info("Failed RPC monitor")
		return fmt.Errorf("couldn't create binding: %s", err)
	}

	//Launch a go func to accept connections
	go r.processRequests()

	return nil
}

// Stop monitoring RPC events.
func (r *rpcMonitor) Stop() error {

	r.listensock.Close()

	os.RemoveAll(r.rpcAddress)

	return nil
}

func (s *Server) addHandler(event monitor.Event, handler RPCEventHandler) {

	s.handlers[event] = handler
}

// HandleEvent Gets called when clients generate events.
func (s *Server) HandleEvent(eventInfo *EventInfo, result *RPCResponse) error {

	if eventInfo.EventType == "" {
		return fmt.Errorf("Invalid event type")
	}

	f, present := s.handlers[eventInfo.EventType]
	if present {
		err := f(eventInfo)
		if err != nil {
			log.WithFields(log.Fields{
				"package": "monitor",
				"error":   err.Error(),
			}).Error("Error while handling event")
			result.Error = err.Error()
		}

		return err
	}

	return nil
}

// generateContextID creates the contextID from the event information
func generateContextID(eventInfo *EventInfo) (string, error) {

	if eventInfo.PUID == "" {
		return "", fmt.Errorf("PUID is empty from eventInfo")
	}

	return eventInfo.PUID, nil
}

// handleCreateEvent handles create events
func (s *Server) handleCreateEvent(eventInfo *EventInfo) error {

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

// handleStartEvent handles start events
func (s *Server) handleStartEvent(eventInfo *EventInfo) error {

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

// handleStopEvent handles a stop event
func (s *Server) handleStopEvent(eventInfo *EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	if !strings.HasPrefix(contextID, cgnetcls.TriremeBasePath) {
		return nil
	}

	contextID = contextID[strings.LastIndex(contextID, "/"):]

	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, monitor.EventStop)
	status := <-errChan

	return status
}

// handleDestroyEvent handles a destroy event
func (s *Server) handleDestroyEvent(eventInfo *EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	if !strings.HasPrefix(contextID, cgnetcls.TriremeBasePath) {
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

// handlePauseEvent handles a pause event
func (s *Server) handlePauseEvent(eventInfo *EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	errChan := s.puHandler.HandlePUEvent(contextID, monitor.EventPause)
	return <-errChan
}
