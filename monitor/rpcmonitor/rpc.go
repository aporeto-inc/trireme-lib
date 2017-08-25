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

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/contextstore"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/policy"
)

var contextStorePath = "/var/run/trireme"

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
}

// Server represents the Monitor RPC Server implementation
type Server struct {
	handlers map[constants.PUType]map[monitor.Event]RPCEventHandler
}

// NewRPCMonitor returns a base RPC monitor. Processors must be registered externally
func NewRPCMonitor(rpcAddress string, collector collector.EventCollector) (*RPCMonitor, error) {

	if rpcAddress == "" {
		return nil, fmt.Errorf("RPC endpoint address invalid")
	}

	if _, err := os.Stat(rpcAddress); err == nil {
		if err := os.Remove(rpcAddress); err != nil {
			return nil, fmt.Errorf("Failed to clean up rpc socket")
		}
	}

	monitorServer := &Server{
		handlers: map[constants.PUType]map[monitor.Event]RPCEventHandler{},
	}

	r := &RPCMonitor{
		rpcAddress:    rpcAddress,
		monitorServer: monitorServer,
		contextstore:  contextstore.NewContextStore(contextStorePath),
		collector:     collector,
	}

	// Registering the monitorRPCServer as an RPC Server.
	r.rpcServer = rpc.NewServer()
	err := r.rpcServer.Register(r.monitorServer)
	if err != nil {
		zap.L().Fatal("Format of service MonitorServer isn't correct", zap.Error(err))
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

	walker, err := r.contextstore.WalkStore()
	if err != nil {
		return fmt.Errorf("error in accessing context store")
	}

	//This is create to only delete if required don't create groups using this handle here
	cgnetclshandle := cgnetcls.NewCgroupNetController("")
	cstorehandle := contextstore.NewContextStore(contextStorePath)

	for {
		contextID := <-walker
		if contextID == "" {
			break
		}

		data, cerr := r.contextstore.GetContextInfo("/" + contextID)
		if cerr != nil || data == nil {
			continue
		}

		var eventInfo EventInfo
		if err := json.Unmarshal(data.([]byte), &eventInfo); err != nil {
			zap.L().Warn("Found invalid state for context - Cleaning up",
				zap.String("contextID", contextID),
				zap.Error(err),
			)

			if rerr := r.contextstore.RemoveContext("/" + contextID); rerr != nil {
				return fmt.Errorf("Failed to remove invalide context for %s", rerr.Error())
			}
			continue
		}

		processlist, err := cgnetcls.ListCgroupProcesses(eventInfo.PUID)
		if err != nil {
			//The cgroup does not exists - log error and remove context
			if cerr := cstorehandle.RemoveContext(eventInfo.PUID); cerr != nil {
				zap.L().Warn("Failed to remove state from store handler", zap.Error(cerr))
			}
			continue
		}

		if len(processlist) <= 0 {
			//We have an empty cgroup
			//Remove the cgroup and context store file
			if err := cgnetclshandle.DeleteCgroup(eventInfo.PUID); err != nil {
				zap.L().Warn("Failed to deleted cgroup",
					zap.String("puID", eventInfo.PUID),
					zap.Error(err),
				)
			}

			if err := cstorehandle.RemoveContext(eventInfo.PUID); err != nil {
				zap.L().Warn("Failed to deleted context",
					zap.String("puID", eventInfo.PUID),
					zap.Error(err),
				)
			}
			continue
		}

		if f, ok := r.monitorServer.handlers[eventInfo.PUType][monitor.EventStart]; ok {
			if err := f(&eventInfo); err != nil {
				return fmt.Errorf("error in processing existing data: %s", err.Error())
			}
		} else {
			return fmt.Errorf("cannot find handler")
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
				zap.L().Error("Error while handling RPC event", zap.Error(err))
			}
			break
		}

		r.rpcServer.ServeCodec(jsonrpc.NewServerCodec(conn))
	}
}

// Start starts the RPC monitoring.
func (r *RPCMonitor) Start() error {

	var err error

	zap.L().Debug("Starting RPC monitor", zap.String("address", r.rpcAddress))

	// Check if we had running units when we last died
	if err = r.reSync(); err != nil {
		return err
	}

	if r.listensock, err = net.Listen("unix", r.rpcAddress); err != nil {
		return fmt.Errorf("Failed to start RPC monitor: couldn't create binding: %s", err.Error())
	}

	if err = os.Chmod(r.rpcAddress, 0766); err != nil {
		return fmt.Errorf("Failed to start RPC monitor: cannot adjust permissions %s", err.Error())
	}

	//Launch a go func to accept connections
	go r.processRequests()

	return nil
}

// Stop monitoring RPC events.
func (r *RPCMonitor) Stop() error {

	if err := r.listensock.Close(); err != nil {
		zap.L().Warn("Failed to stop rpc monitor", zap.Error(err))
	}

	if err := os.RemoveAll(r.rpcAddress); err != nil {
		zap.L().Warn("Failed to cleanup rpc monitor socket", zap.Error(err))
	}

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
				result.Error = err.Error()
				return fmt.Errorf("Error")
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

	runtimeTags := policy.NewTagStoreFromMap(event.Tags)
	runtimeIps := event.IPs
	runtimePID, err := strconv.Atoi(event.PID)
	if err != nil {
		return nil, fmt.Errorf("PID is invalid: %s", err)
	}

	return policy.NewPURuntime(event.Name, runtimePID, runtimeTags, runtimeIps, constants.ContainerPU, nil), nil
}
