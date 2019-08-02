package enforcerproxy

import (
	"errors"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.uber.org/zap"
)

// ProxyRPCServer This struct is a receiver for Statsserver and maintains a handle to the RPC ProxyRPCServer.
type ProxyRPCServer struct {
	collector collector.EventCollector
	rpchdl    rpcwrapper.RPCServer
	secret    string
}

// PostStats is the function called from the remoteenforcer when it has new flow events to publish.
func (r *ProxyRPCServer) PostStats(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !r.rpchdl.ProcessMessage(&req, r.secret) {
		return errors.New("message sender cannot be verified")
	}

	payload := req.Payload.(rpcwrapper.StatsPayload)

	for _, record := range payload.Flows {
		r.collector.CollectFlowEvent(record)
	}

	for _, record := range payload.Users {
		r.collector.CollectUserEvent(record)
	}

	return nil
}

// PostPacketEvent is called from the remote to post multiple records from the remoteenforcer
func (r *ProxyRPCServer) PostPacketEvent(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	if !r.rpchdl.ProcessMessage(&req, r.secret) {
		return errors.New("message sender cannot be verified")
	}

	payload := req.Payload.(rpcwrapper.DebugPacketPayload)
	for _, record := range payload.PacketRecords {

		r.collector.CollectPacketEvent(record)
	}
	return nil
}

// PostCounterEvent is called from the remote to post multiple counter records from the remoteenforcer
func (r *ProxyRPCServer) PostCounterEvent(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	if !r.rpchdl.ProcessMessage(&req, r.secret) {
		return errors.New("message sender cannot be verified")
	}

	payload := req.Payload.(rpcwrapper.CounterReportPayload)
	for _, record := range payload.CounterReports {
		zap.L().Debug("Posting Remote counters")
		r.collector.CollectCounterEvent(record)
	}
	return nil
}
