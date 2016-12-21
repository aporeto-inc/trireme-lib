package monitor

import (
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/docker/docker/api/types/events"
)

// A RPCMetadataExtractor is a function used to extract a *policy.PURuntime from a given
// docker ContainerJSON.
type RPCMetadataExtractor func() (*policy.PURuntime, error)

// rpcMonitor implements the RPC connection monitoring
type rpcMonitor struct {
	metadataExtractor  RPCMetadataExtractor
	handlers           map[DockerEvent]func(event *events.Message) error
	eventnotifications chan *events.Message
	stopprocessor      chan bool
	stoplistener       chan bool
	syncAtStart        bool

	puHandler ProcessingUnitsHandler
}

// NewRPCMonitor is a
func NewRPCMonitor(
	socketType string,
	socketAddress string,
	p ProcessingUnitsHandler,
	m RPCMetadataExtractor,
	l collector.EventCollector, syncAtStart bool,
) Monitor {

	r := &rpcMonitor{}

	return r
}

// Start starts the RPC monitoring.
func (r *rpcMonitor) Start() error {
	return nil
}

// Stop monitoring RPC events.
func (r *rpcMonitor) Stop() error {
	return nil
}
