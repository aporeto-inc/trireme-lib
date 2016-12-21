package monitor

import (
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"strconv"

	log "github.com/Sirupsen/logrus"

	"github.com/aporeto-inc/trireme/collector"
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

	return policy.NewPURuntime(event.Name, runtimePID, runtimeTags, runtimeIps), nil
}

// A RPCEventHandler is type of docker event handler functions.
type RPCEventHandler func(*EventInfo) error

// rpcMonitor implements the RPC connection
type rpcMonitor struct {
	rpcAddress    string
	rpcServer     *rpc.Server
	monitorServer *Server
}

// Server represents the Monitor RPC Server implementation
type Server struct {
	handlers          map[Event]RPCEventHandler
	metadataExtractor RPCMetadataExtractor
	collector         collector.EventCollector
	puHandler         ProcessingUnitsHandler
}

// NewRPCMonitor returns a fully initialized RPC Based monitor.
func NewRPCMonitor(rpcAddress string, metadataExtractor RPCMetadataExtractor, puHandler ProcessingUnitsHandler, collector collector.EventCollector) (Monitor, error) {

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
		handlers:          map[Event]RPCEventHandler{},
	}

	if metadataExtractor == nil {
		monitorServer.metadataExtractor = defaultRPCMetadataExtractor
	}

	monitorServer.addHandler(EventStart, monitorServer.handleStartEvent)
	monitorServer.addHandler(EventStop, monitorServer.handleStopEvent)
	monitorServer.addHandler(EventCreate, monitorServer.handleCreateEvent)
	monitorServer.addHandler(EventDestroy, monitorServer.handleDestroyEvent)
	monitorServer.addHandler(EventPause, monitorServer.handlePauseEvent)

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
	listener, err := net.Listen("unix", r.rpcAddress)
	if err != nil {
		return fmt.Errorf("couldn't create binding: %s", err)
	}
	defer listener.Close()

	log.WithFields(log.Fields{
		"package": "monitor",
	}).Debugf("Starting RPC Server and listening at endpoint: %s", r.rpcAddress)

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
		}

		r.rpcServer.ServeCodec(jsonrpc.NewServerCodec(conn))
	}
}

// Stop monitoring RPC events.
func (r *rpcMonitor) Stop() error {
	return nil
}

func (s *Server) addHandler(event Event, handler RPCEventHandler) {
	s.handlers[event] = handler
}

// HandleEvent Gets called when clients generate events.
func (s *Server) HandleEvent(eventInfo *EventInfo, result *RPCResponse) error {
	log.Debugf("Handling RPC eventof type %s", eventInfo.EventType)

	f, present := s.handlers[eventInfo.EventType]
	if present {

		err := f(eventInfo)

		if err != nil {
			log.WithFields(log.Fields{
				"package": "monitor",
				"error":   err.Error(),
			}).Error("Error while handling event")
		}
	} else {
		log.Debugf("RPC event not handled.")
	}

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

	// TODO: Adapt to generic PU
	s.collector.CollectContainerEvent(contextID, "", nil, collector.ContainerCreate)

	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, EventCreate)
	return <-errChan
}

func (s *Server) handleStartEvent(eventInfo *EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	runtimeInfo, err := s.metadataExtractor(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate RuntimeInfo: %s", err)
	}

	s.puHandler.SetPURuntime(contextID, runtimeInfo)

	defaultIP, _ := runtimeInfo.DefaultIPAddress()

	s.collector.CollectContainerEvent(contextID, defaultIP, runtimeInfo.Tags(), collector.ContainerStart)

	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, EventStart)
	return <-errChan
}

func (s *Server) handleStopEvent(eventInfo *EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, EventStop)
	return <-errChan
}

func (s *Server) handleDestroyEvent(eventInfo *EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, EventDestroy)
	return <-errChan
}

func (s *Server) handlePauseEvent(eventInfo *EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	errChan := s.puHandler.HandlePUEvent(contextID, EventPause)
	return <-errChan
}
