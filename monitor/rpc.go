package monitor

import (
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"

	log "github.com/Sirupsen/logrus"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/policy"
)

// RPCMetadataExtractor is a function used to extract a *policy.PURuntime from a given
// EventInfo.
type RPCMetadataExtractor func(EventInfo) (*policy.PURuntime, error)

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
func NewRPCMonitor(rpcAddress string, metadataExtractor RPCMetadataExtractor, puHandler ProcessingUnitsHandler, collector collector.EventCollector) Monitor {

	monitorServer := &Server{
		collector:         collector,
		puHandler:         puHandler,
		metadataExtractor: metadataExtractor,
		handlers:          map[Event]RPCEventHandler{},
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

	r.rpcServer = rpc.NewServer()
	err := r.rpcServer.Register(r.monitorServer)
	if err != nil {
		log.Fatalf("Format of service MonitorServer isn't correct. %s", err)
	}

	return r
}

// Start starts the RPC monitoring.
func (r *rpcMonitor) Start() error {
	listener, err := net.Listen("unix", r.rpcAddress)
	if err != nil {
		log.Fatal("listen error:", err)
	}

	for {
		fmt.Println("Handling new request")
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go r.rpcServer.ServeCodec(jsonrpc.NewServerCodec(conn))
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
	fmt.Printf("Received an event of type: %+v ", eventInfo.EventType)

	f, present := s.handlers[eventInfo.EventType]
	if present {
		log.WithFields(log.Fields{
			"package": "monitor",
		}).Debug("Handling RPC event")

		err := f(eventInfo)

		if err != nil {
			log.WithFields(log.Fields{
				"package": "monitor",
				"error":   err.Error(),
			}).Error("Error while handling event")
		}
	} else {
		log.WithFields(log.Fields{
			"package": "monitor",
		}).Debug("RPC event not handled.")
	}

	return nil
}

func generateContextID(eventInfo *EventInfo) (string, error) {
	return eventInfo.PUID, nil
}

func (s *Server) handleCreateEvent(eventInfo *EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID")
	}

	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, EventCreate)
	return <-errChan
}

func (s *Server) handleStartEvent(eventInfo *EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID")
	}

	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, EventStart)
	return <-errChan
}

func (s *Server) handleStopEvent(eventInfo *EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID")
	}

	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, EventStop)
	return <-errChan
}

func (s *Server) handleDestroyEvent(eventInfo *EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID")
	}

	// Send the event upstream
	errChan := s.puHandler.HandlePUEvent(contextID, EventDestroy)
	return <-errChan
}

func (s *Server) handlePauseEvent(eventInfo *EventInfo) error {
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID")
	}

	errChan := s.puHandler.HandlePUEvent(contextID, EventPause)
	return <-errChan
}
