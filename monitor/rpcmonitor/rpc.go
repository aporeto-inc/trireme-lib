package rpcmonitor

import (
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/monitor/eventinfo"
	"github.com/aporeto-inc/trireme-lib/monitor/processor"
)

const (

	// DefaultRPCAddress is the default Linux socket for the RPC monitor
	DefaultRPCAddress = "/var/run/trireme.sock"

	// DefaultRootRPCAddress creates an RPC listener that requires root credentials
	DefaultRootRPCAddress = "/var/run/triremeroot.sock"
)

// A RPCEventHandler is type of event handler functions.
type RPCEventHandler func(*eventinfo.EventInfo) error

// RPCResponse encapsulate the error response if any.
type RPCResponse struct {
	Error string
}

// RPCMonitor implements the RPC connection
type RPCMonitor struct {
	rpcAddress    string
	rpcServer     *rpc.Server
	monitorServer *Server
	listensock    net.Listener
	collector     collector.EventCollector
	puHandler     monitor.ProcessingUnitsHandler
	syncHandler   monitor.SynchronizationHandler
	root          bool
}

const (
	maxEventNameLength = 64
)

// NewRPCMonitor returns a base RPC monitor. Processors must be registered externally
func NewRPCMonitor(rpcAddress string, collector collector.EventCollector, root bool) (*RPCMonitor, error) {

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
func (r *RPCMonitor) RegisterProcessor(puType constants.PUType, p processor.EventProcessor) error {

	return r.monitorServer.RegisterProcessor(puType, p)
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

// SetupHandlers installs handlers
func (r *RPCMonitor) SetupHandlers(p monitor.ProcessingUnitsHandler, s monitor.SynchronizationHandler) {

	r.puHandler = p
	r.syncHandler = s
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
		return fmt.Errorf("Failed to start RPC monitor: couldn't create binding: %s", err.Error())
	}

	if r.root {
		err = os.Chmod(r.rpcAddress, 0600)
	} else {
		err = os.Chmod(r.rpcAddress, 0766)
	}

	if err != nil {
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
