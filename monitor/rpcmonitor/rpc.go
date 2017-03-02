package rpcmonitor

import (
	"encoding/json"
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/contextstore"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/policy"
)

// RPCMetadataExtractor is a function used to extract a *policy.PURuntime from a given
// EventInfo.
type RPCMetadataExtractor func(*EventInfo) (*policy.PURuntime, error)

// A RPCEventHandler is type of docker event handler functions.
type RPCEventHandler func(*EventInfo) error

// RPCMonitor implements the RPC connection
type RPCMonitor struct {
	rpcAddress    string
	rpcServer     *rpc.Server
	monitorServer *Server
	listensock    net.Listener
	contextstore  contextstore.ContextStore
	collector     collector.EventCollector
	puHandler     monitor.ProcessingUnitsHandler
}

// Server represents the Monitor RPC Server implementation
type Server struct {
	handlers map[constants.PUType]map[monitor.Event]RPCEventHandler
}

// NewRPCMonitor returns a base RPC monitor. Processors must be registered externally
func NewRPCMonitor(rpcAddress string, puHandler monitor.ProcessingUnitsHandler, collector collector.EventCollector) (*RPCMonitor, error) {

	if rpcAddress == "" {
		return nil, fmt.Errorf("RPC endpoint address invalid")
	}

	if _, err := os.Stat(rpcAddress); err == nil {
		if err := os.Remove(rpcAddress); err != nil {
			return nil, fmt.Errorf("Failed to clean up rpc socket")
		}
	}

	if puHandler == nil {
		return nil, fmt.Errorf("PU Handler required")
	}

	monitorServer := &Server{
		handlers: map[constants.PUType]map[monitor.Event]RPCEventHandler{},
	}

	r := &RPCMonitor{
		rpcAddress:    rpcAddress,
		monitorServer: monitorServer,
		contextstore:  contextstore.NewContextStore(),
		collector:     collector,
	}

	// Registering the monitorRPCServer as an RPC Server.
	r.rpcServer = rpc.NewServer()
	err := r.rpcServer.Register(r.monitorServer)
	if err != nil {
		log.Fatalf("Format of service MonitorServer isn't correct. %s", err)
	}

	return r, nil
}

// RegisterProcessor registers an event processor for a given PUTYpe. Only one
// processor is allowed for a given PU Type.
func (r *RPCMonitor) RegisterProcessor(puType constants.PUType, processor MonitorProcessor) error {
	if _, ok := r.monitorServer.handlers[puType]; ok {
		return fmt.Errorf("Processor already registered for this PU type %d ", puType)
	}

	r.monitorServer.handlers[puType] = map[monitor.Event]RPCEventHandler{}

	r.monitorServer.addHandler(puType, monitor.EventStart, processor.Start)
	r.monitorServer.addHandler(puType, monitor.EventStop, processor.Stop)
	r.monitorServer.addHandler(puType, monitor.EventCreate, processor.Create)
	r.monitorServer.addHandler(puType, monitor.EventDestroy, processor.Destroy)
	r.monitorServer.addHandler(puType, monitor.EventPause, processor.Pause)

	return nil
}

// reSync resyncs with all the existing services that were there before we start
func (r *RPCMonitor) reSync() error {

	var eventInfo EventInfo

	walker, err := r.contextstore.WalkStore()

	if err != nil {

		return fmt.Errorf("error in accessing context store")
	}
	//This is create to only delete if required don't create groups using this handle here
	cgnetclshandle := cgnetcls.NewCgroupNetController("")
	cstorehandle := contextstore.NewContextStore()
	for {
		contextID := <-walker
		if contextID == "" {
			break
		}

		data, err := r.contextstore.GetContextInfo("/" + contextID)
		if err == nil && data != nil {

			if err := json.Unmarshal(data.([]byte), &eventInfo); err != nil {
				return fmt.Errorf("error in umarshalling date")
			}
			processlist, err := cgnetcls.ListCgroupProcesses(eventInfo.PUID)

			if err != nil {
				cstorehandle.RemoveContext(eventInfo.PUID)
				//The cgroup does not exists
				continue
			}

			if len(processlist) <= 0 {
				//We have an empty cgroup
				//Remove the cgroup and context store file
				cgnetclshandle.DeleteCgroup(eventInfo.PUID)
				cstorehandle.RemoveContext(eventInfo.PUID)
				continue
			}
			f, _ := r.monitorServer.handlers[eventInfo.PUType][monitor.EventStart]

			if err := f(&eventInfo); err != nil {
				return fmt.Errorf("error in processing existing data")
			}
		}
	}

	return nil
}

// processRequests processes the RPC requests
func (r *RPCMonitor) processRequests() {
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
func (r *RPCMonitor) Start() error {

	var err error

	log.WithFields(log.Fields{"package": "RPCMonitor",
		"message:": "Starting rpc monitor",
		"socket":   r.rpcAddress,
	}).Info("Starting RPC monitor")

	// Check if we had running units when we last died
	if err = r.reSync(); err != nil {
		log.WithFields(log.Fields{
			"package":  "RPCMonitor",
			"error":    err.Error(),
			"message:": "Unable to resync existing services",
		}).Error("Failed to resync existing services")
	}

	if r.listensock, err = net.Listen("unix", r.rpcAddress); err != nil {
		log.WithFields(log.Fields{"package": "RPCMonitor",
			"error":    err.Error(),
			"message:": "Starting",
		}).Info("Failed RPC monitor")
		return fmt.Errorf("couldn't create binding: %s", err)
	}

	if err = os.Chmod(r.rpcAddress, 0766); err != nil {
		log.WithFields(log.Fields{"package": "RPCMonitor",
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
func (r *RPCMonitor) Stop() error {

	r.listensock.Close()

	os.RemoveAll(r.rpcAddress)

	return nil
}

func (s *Server) addHandler(puType constants.PUType, event monitor.Event, handler RPCEventHandler) {

	s.handlers[puType][event] = handler
}

// HandleEvent Gets called when clients generate events.
func (s *Server) HandleEvent(eventInfo *EventInfo, result *RPCResponse) error {

	if eventInfo.EventType == "" {
		return fmt.Errorf("Invalid event type")
	}

	if _, ok := s.handlers[eventInfo.PUType]; ok {
		f, present := s.handlers[eventInfo.PUType][eventInfo.EventType]
		if present {
			if err := f(eventInfo); err != nil {
				log.WithFields(log.Fields{
					"package": "monitor",
					"error":   err.Error(),
				}).Error("Error while handling event")
				result.Error = err.Error()
				return err
			}
			return nil
		}
	}

	err := fmt.Errorf("No handler found for the event")
	result.Error = err.Error()
	return err

}

// DefaultRPCMetadataExtractor is a default RPC metadata extractor for testing
func DefaultRPCMetadataExtractor(event *EventInfo) (*policy.PURuntime, error) {

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

	return policy.NewPURuntime(event.Name, runtimePID, runtimeTags, runtimeIps, constants.ContainerPU, nil), nil
}
