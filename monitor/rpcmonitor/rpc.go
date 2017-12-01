package rpcmonitor

import (
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"regexp"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// RPCMetadataExtractor is a function used to extract a *policy.PURuntime from a given
// EventInfo.
type RPCMetadataExtractor func(*EventInfo) (*policy.PURuntime, error)

// A RPCEventHandler is type of event handler functions.
type RPCEventHandler func(*EventInfo) error

// RPCMonitor implements the RPC connection
type RPCMonitor struct {
	rpcAddress    string
	rpcServer     *rpc.Server
	monitorServer *Server
	listensock    net.Listener
	collector     collector.EventCollector
	root          bool
}

const (
	maxEventNameLength = 64
)

// NewRPCMonitor returns a base RPC monitor. Processors must be registered externally
func NewRPCMonitor(rpcAddress string, collector collector.EventCollector, root bool) (*RPCMonitor, error) {

	if rpcAddress == "" {
		return nil, fmt.Errorf("empty rpc endpoint address")
	}

	if _, err := os.Stat(rpcAddress); err == nil {
		if err := os.Remove(rpcAddress); err != nil {
			return nil, fmt.Errorf("unable to clean up rpc socket: %s", err)
		}
	}

	monitorServer := &Server{
		handlers: map[constants.PUType]map[monitor.Event]RPCEventHandler{},
		root:     root,
	}

	r := &RPCMonitor{
		rpcAddress:    rpcAddress,
		monitorServer: monitorServer,
		collector:     collector,
		root:          root,
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
		return fmt.Errorf("processor already registered for this pu of type %d ", puType)
	}

	r.monitorServer.handlers[puType] = map[monitor.Event]RPCEventHandler{}

	r.monitorServer.addHandler(puType, monitor.EventStart, processor.Start)
	r.monitorServer.addHandler(puType, monitor.EventStop, processor.Stop)
	r.monitorServer.addHandler(puType, monitor.EventCreate, processor.Create)
	r.monitorServer.addHandler(puType, monitor.EventDestroy, processor.Destroy)
	r.monitorServer.addHandler(puType, monitor.EventPause, processor.Pause)
	r.monitorServer.addHandler(puType, monitor.EventResync, processor.ReSync)

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

		go r.rpcServer.ServeCodec(jsonrpc.NewServerCodec(conn))
	}
}

// Start starts the RPC monitoring.
func (r *RPCMonitor) Start() error {

	var err error

	zap.L().Debug("Starting RPC monitor", zap.String("address", r.rpcAddress))

	// Check if we had running units when we last died
	if err = r.monitorServer.reSync(); err != nil {
		return err
	}

	if r.listensock, err = net.Listen("unix", r.rpcAddress); err != nil {
		return fmt.Errorf("failed to start rpc monitor: couldn't create binding: %s", err)
	}

	if r.root {
		err = os.Chmod(r.rpcAddress, 0600)
	} else {
		err = os.Chmod(r.rpcAddress, 0766)
	}

	if err != nil {
		return fmt.Errorf("failed to start rpc monitor: cannot adjust permissions: %s", err)
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

// Server represents the Monitor RPC Server implementation
type Server struct {
	handlers map[constants.PUType]map[monitor.Event]RPCEventHandler
	root     bool
}

// HandleEvent Gets called when clients generate events.
func (s *Server) HandleEvent(eventInfo *EventInfo, result *RPCResponse) error {

	if err := validateEvent(eventInfo); err != nil {
		return err
	}

	if eventInfo.HostService && !s.root {
		return fmt.Errorf("operation requires root access")
	}

	strtokens := eventInfo.PUID[strings.LastIndex(eventInfo.PUID, "/")+1:]
	if _, ferr := os.Stat("/var/run/trireme/linux/" + strtokens); os.IsNotExist(ferr) && eventInfo.EventType != monitor.EventCreate && eventInfo.EventType != monitor.EventStart {
		eventInfo.PUType = constants.UIDLoginPU
	}

	if _, ok := s.handlers[eventInfo.PUType]; ok {
		f, present := s.handlers[eventInfo.PUType][eventInfo.EventType]
		if present {
			if err := f(eventInfo); err != nil {
				result.Error = err.Error()
				return err
			}
			return nil
		}
	}

	err := fmt.Errorf("no handler found for the event")
	result.Error = err.Error()
	return err

}

// addHandler adds a hadler for a given PU and monitor event
func (s *Server) addHandler(puType constants.PUType, event monitor.Event, handler RPCEventHandler) {

	s.handlers[puType][event] = handler
}

// ReSync handles a server resync
func (s *Server) reSync() error {

	for _, h := range s.handlers {
		if err := h[monitor.EventResync](nil); err != nil {
			return err
		}
	}

	return nil
}

// DefaultRPCMetadataExtractor is a default RPC metadata extractor for testing
func DefaultRPCMetadataExtractor(event *EventInfo) (*policy.PURuntime, error) {

	runtimeTags := policy.NewTagStore()
	runtimeTags.Tags = event.Tags

	runtimeIps := event.IPs
	runtimePID, err := strconv.Atoi(event.PID)
	if err != nil {
		return nil, fmt.Errorf("invalid pid: %s", err)
	}

	return policy.NewPURuntime(event.Name, runtimePID, "", runtimeTags, runtimeIps, constants.ContainerPU, nil), nil
}

func validateEvent(event *EventInfo) error {

	if event.EventType == monitor.EventCreate || event.EventType == monitor.EventStart {
		if len(event.Name) > maxEventNameLength {
			return fmt.Errorf("invalid event name: must not be nil or greater than 64 characters")
		}

		if event.PID == "" {
			return fmt.Errorf("invalid pid: empty")
		}

		pid, err := strconv.Atoi(event.PID)
		if err != nil {
			return fmt.Errorf("invalid pid: %s", err)
		}
		if pid < 0 {
			return fmt.Errorf("invalid pid: must be a positive number")
		}

		if event.HostService {
			if event.NetworkOnlyTraffic {
				if event.Name == "" || event.Name == "default" {
					return fmt.Errorf("service name must be provided and must be not be default")
				}
				event.PUID = event.Name
			} else {
				event.Name = "DefaultServer"
				event.PUID = "default"
			}

		} else {
			if event.PUType != constants.UIDLoginPU || event.PUID == "" {
				event.PUID = event.PID
			}

			// if event.EventType == monitor.EventDestroy {
			// 	event.PUID = event.PID
			// }
		}
	}

	if event.EventType == monitor.EventStop || event.EventType == monitor.EventDestroy {
		regStop := regexp.MustCompile("^/trireme/[a-zA-Z0-9_].{0,11}$")
		if event.Cgroup != "" && !regStop.Match([]byte(event.Cgroup)) {
			return fmt.Errorf("cgroup is not of the right format")
		}
	}

	return nil
}
