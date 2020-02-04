package enforcerproxy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
)

// ProxyRPCServer This struct is a receiver for Statsserver and maintains a handle to the RPC ProxyRPCServer.
type ProxyRPCServer struct {
	collector   collector.EventCollector
	rpchdl      rpcwrapper.RPCServer
	secret      string
	tokenIssuer common.ServiceTokenIssuer
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
	payload.Flows = nil

	for _, record := range payload.Users {
		r.collector.CollectUserEvent(record)
	}
	payload.Users = nil

	return nil
}

// RetrieveToken propagates the master request to the token retriever and returns a token.
func (r *ProxyRPCServer) RetrieveToken(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !r.rpchdl.ProcessMessage(&req, r.secret) {
		return errors.New("message sender cannot be verified")
	}

	payload, ok := req.Payload.(rpcwrapper.TokenRequestPayload)
	if !ok {
		return errors.New("invalid request payload for token request")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	token, err := r.tokenIssuer.Issue(ctx, payload.ContextID, payload.ServiceTokenType, payload.Audience, payload.Validity)
	if err != nil {
		resp.Status = "error"
		return fmt.Errorf("control plane failed to issue token: %s", err)
	}

	resp.Status = "ok"
	resp.Payload = &rpcwrapper.TokenResponsePayload{
		Token: token,
	}

	return nil
}

// PostReportEvent posts report events to the listener.
func (r *ProxyRPCServer) PostReportEvent(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !r.rpchdl.ProcessMessage(&req, r.secret) {
		return errors.New("message sender cannot be verified")
	}

	switch req.PayloadType {
	case rpcwrapper.PingReport:
		pingReport := req.Payload.(*collector.PingReport)
		r.collector.CollectPingEvent(pingReport)

	case rpcwrapper.DebugReport:
		debugReport := req.Payload.(*collector.PacketReport)
		r.collector.CollectPacketEvent(debugReport)

	case rpcwrapper.CounterReport:
		counterReport := req.Payload.(*collector.CounterReport)
		r.collector.CollectCounterEvent(counterReport)

	case rpcwrapper.DNSReport:
		dnsReport := req.Payload.(*collector.DNSRequestReport)
		r.collector.CollectDNSRequests(dnsReport)

	default:
		return fmt.Errorf("unsupported report type: %v", req.PayloadType)
	}

	req.Payload = nil
	return nil
}
