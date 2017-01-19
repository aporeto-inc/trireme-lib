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

//NewRPCoMonitor returns a fully initialized RPC Based monitor.
func NewRPCMonitor(rpcAddress string, metadataExtractor RPCMetadataExtractor, puHandler monitor.ProcessingUnitsHandler, collector collector.EventCollector, netcls cgnetcls.Cgroupnetcls, contextstorehdl contextstore.ContextStore) (monitor.Monitor, error) {

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

// Start starts the RPC monitoring.
// Blocking, so needs to be started with go...
func (r *rpcMonitor) Start() error {

	log.WithFields(log.Fields{"package": "rpcmonitor",
		"message:": "Starting",
	}).Info("Starting RPC monitor")

	//Check if we had running units when we last died
	//Ideally want to recreate these

	walker, err := r.monitorServer.contextstore.WalkStore()
	if err == nil {

		for {
			contextID := <-walker
			if contextID == "" {
				break
			}
			contextID = "/" + contextID
			data, err := r.monitorServer.contextstore.GetContextInfo(contextID)
			if err == nil && data != nil {
				var eventInfo EventInfo
				json.Unmarshal(data.([]byte), &eventInfo)

				r.monitorServer.handleStartEvent(&eventInfo)
			}
		}
	}
	//TODO END

	listener, err := net.Listen("unix", r.rpcAddress)
	r.listensock = listener
	os.Chmod(r.rpcAddress, 0766)
	if err != nil {
		log.WithFields(log.Fields{"package": "rpcmonitor",
			"error":    err.Error(),
			"message:": "Starting",
		}).Info("Failed RPC monitor")
		return fmt.Errorf("couldn't create binding: %s", err)
	}

	log.WithFields(log.Fields{
		"package": "monitor",
	}).Debugf("Starting RPC Server and listening at endpoint: %s", r.rpcAddress)
	//Launch a go func to accept connections
	go func() {

		for {
			log.WithFields(log.Fields{
				"package": "monitor",
			}).Debugf("Handling new RPC Monitor request")

			conn, err := listener.Accept()
			if err != nil {
				log.WithFields(log.Fields{
					"package": "monitor",
					"error":   err.Error(),
				}).Error("Error while handling RPC event")
				break
			}

			r.rpcServer.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()
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

	log.Debugf("Handling RPC eventof type %s", eventInfo.EventType)

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
	log.Debugf("RPC event not handled.")
	return nil
}

func generateContextID(eventInfo *EventInfo) (string, error) {

	if eventInfo.PUID == "" {
		return "", fmt.Errorf("PUID is empty from eventInfo")
	}
	return eventInfo.PUID, nil
}

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

func (s *Server) handleStartEvent(eventInfo *EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}
	contextStore := contextstore.NewContextStore()

	runtimeInfo, err := s.metadataExtractor(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate RuntimeInfo: %s", err)
	}

	s.puHandler.SetPURuntime(contextID, runtimeInfo)

	defaultIP, _ := runtimeInfo.DefaultIPAddress()

	// Send the event upstream

	errChan := s.puHandler.HandlePUEvent(contextID, monitor.EventStart)

	status := <-errChan
	if nil == status {
		//It is okay to launch this so let us create a cgroup for it

		s.collector.CollectContainerEvent(contextID, defaultIP, runtimeInfo.Tags(), collector.ContainerStart)

		err = s.netcls.Creategroup(eventInfo.PUID)
		if err != nil {
			log.WithFields(log.Fields{"package": "rpcMonitor",
				"error": err.Error()}).Info("Error Creating cgroup")
			return err

		}

		// TODO - Get a mark id for this cgroup
		markval, ok := runtimeInfo.Options().Get(cgnetcls.CgroupMarkTag)
		if !ok {
			s.netcls.DeleteCgroup(eventInfo.PUID)
			log.WithFields(log.Fields{"package": "rpcmonitor",
				"PUID": eventInfo.PUID}).Error("Mark value not found")
			return errors.New("Mark value not found")
		}

		mark, _ := strconv.ParseUint(markval, 10, 32)
		err = s.netcls.AssignMark(eventInfo.PUID, mark)
		if err != nil {
			s.netcls.DeleteCgroup(eventInfo.PUID)
			log.WithFields(log.Fields{"package": "rpcMonitor",
				"error": err.Error()}).Info("Error assigning mark value")
			return err

		}

		pid, _ := strconv.Atoi(eventInfo.PID)
		err = s.netcls.AddProcess(eventInfo.PUID, pid)
		if err != nil {
			s.netcls.DeleteCgroup(eventInfo.PUID)
			log.WithFields(log.Fields{"package": "rpcMonitor",
				"error": err.Error()}).Info("Error adding process")
			return err

		}

	}
	//ContextInfo Store
	contextStore.StoreContext(contextID, eventInfo)
	return status
}

func (s *Server) handleStopEvent(eventInfo *EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	contextID = contextID[strings.LastIndex(contextID, "/"):]

	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, monitor.EventStop)
	status := <-errChan

	return status
}

func (s *Server) handleDestroyEvent(eventInfo *EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
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

func (s *Server) handlePauseEvent(eventInfo *EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	errChan := s.puHandler.HandlePUEvent(contextID, monitor.EventPause)
	return <-errChan
}
