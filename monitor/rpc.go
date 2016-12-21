package monitor

import (
	"fmt"
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/policy"
)

// A RPCMetadataExtractor is a function used to extract a *policy.PURuntime from a given
// docker ContainerJSON.
type RPCMetadataExtractor func() (*policy.PURuntime, error)

// rpcMonitor implements the RPC connection monitoring
type rpcMonitor struct {
	rpcAddress    string
	rpcServer     *rpc.Server
	monitorServer *Server
}

// Server represents the RPC server implementation
type Server struct {
	handlers          map[Event]func(EventInfo *EventInfo) error
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
	}

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
	listener, e := net.Listen("unix", r.rpcAddress)
	if e != nil {
		log.Fatal("listen error:", e)
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

// HandleEvent Gets called on Events
func (r *Server) HandleEvent(eventInfo *EventInfo, result *RPCResponse) error {
	fmt.Printf("Received an event: %+v ", eventInfo)
	return nil
}
