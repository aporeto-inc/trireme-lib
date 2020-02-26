package reports

import (
	"context"
	"errors"
	"os"

	"go.aporeto.io/trireme-lib/v11/controller/constants"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/remoteenforcer/internal/client"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/remoteenforcer/internal/statscollector"
	"go.uber.org/zap"
)

const (
	reportContextID  = "UNUSED"
	reportRPCCommand = "ProxyRPCServer.PostReportEvent"
)

// reportClient  This is the struct for storing state for the rpc client
// which reports events back to the controller process
type reportsClient struct {
	collector     statscollector.Collector
	rpchdl        *rpcwrapper.RPCWrapper
	secret        string
	reportChannel string
	stop          chan bool
}

// NewClient initializes a new ping report client
func NewClient(cr statscollector.Collector) (client.Reporter, error) {

	p := &reportsClient{
		collector:     cr,
		rpchdl:        rpcwrapper.NewRPCWrapper(),
		secret:        os.Getenv(constants.EnvStatsSecret),
		reportChannel: os.Getenv(constants.EnvStatsChannel),
		stop:          make(chan bool),
	}

	if p.reportChannel == "" {
		return nil, errors.New("no path to stats socket provided")
	}

	if p.secret == "" {
		return nil, errors.New("no secret provided for stats channel")
	}

	return p, nil
}

func (p *reportsClient) sendStats(ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			return
		case r := <-p.collector.GetReports():
			p.sendRequest(r)
		}
	}
}

func (p *reportsClient) sendRequest(report *statscollector.Report) {

	request := rpcwrapper.Request{
		PayloadType: reportTypeToPayloadType(report.Type),
		Payload:     report.Payload,
	}

	if err := p.rpchdl.RemoteCall(
		reportContextID,
		reportRPCCommand,
		&request,
		&rpcwrapper.Response{},
	); err != nil {
		zap.L().Error("unable to execute rpc", zap.Error(err))
	}
}

// Start This is an private function called by the remoteenforcer to connect back
// to the controller over a stats channel
func (p *reportsClient) Run(ctx context.Context) error {
	if err := p.rpchdl.NewRPCClient(reportContextID, p.reportChannel, p.secret); err != nil {
		zap.L().Error("unable to create new rpc client", zap.Error(err))
		return err
	}

	go p.sendStats(ctx)

	return nil
}

// Send is unimplemented.
func (p *reportsClient) Send() error {
	return nil
}

func reportTypeToPayloadType(rtype statscollector.ReportType) (ptype rpcwrapper.PayloadType) {

	switch rtype {
	case statscollector.PacketReport:
		ptype = rpcwrapper.PacketReport
	case statscollector.CounterReport:
		ptype = rpcwrapper.CounterReport
	case statscollector.DNSReport:
		ptype = rpcwrapper.DNSReport
	case statscollector.PingReport:
		ptype = rpcwrapper.PingReport
	default:
		return
	}

	return ptype
}
