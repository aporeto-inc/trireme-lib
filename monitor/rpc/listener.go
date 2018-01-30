package rpcmonitor

import (
	"context"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/monitor/rpc/eventserver"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/registerer"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/server"
)

const (
	// DefaultRPCAddress is the default Linux socket for the RPC monitor
	DefaultRPCAddress = "/var/run/trireme.sock"

	// DefaultRootRPCAddress creates an RPC listener that requires root credentials
	DefaultRootRPCAddress = "/var/run/triremeroot.sock"
)

// listener implements the RPC connection
type listener struct {
	// rpcServer is our RPC channel
	rpcServer rpcserver.RPCServer
	// eventProcessor uses rpcServer with a type event.EventInfo and mux's the events
	// for a given type to an event processor.
	eventProcessor eventserver.Processor
	registerer     registerer.Registerer
}

// New returns a base RPC listener. Processors must be registered externally
func New(rpcAddress string, root bool) (Listener, registerer.Registerer, error) {

	l := &listener{
		rpcServer: rpcserver.New(rpcAddress, root),
	}
	l.eventProcessor, l.registerer = eventserver.New(root)

	if err := l.rpcServer.Register(l.eventProcessor); err != nil {
		return nil, nil, err
	}

	return l, l.registerer, nil
}

// Run monitoring RPC events.
func (l *listener) Run(ctx context.Context) (err error) {

	zap.L().Debug("Starting RPC monitor")

	return l.rpcServer.Run(ctx)
}
