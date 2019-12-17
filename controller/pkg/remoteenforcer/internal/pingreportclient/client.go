package pingreportclient

import (
	"context"
	"errors"
	"os"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/statscollector"
	"go.uber.org/zap"
)

const (
	pingReportContextID = "UNUSED"
	pingRPCCommand      = "ProxyRPCServer.PostPingEvent"
)

// pingReportClient  This is the struct for storing state for the rpc client
// which reports ping events back to the controller process
type pingReportClient struct {
	collector         statscollector.Collector
	rpchdl            *rpcwrapper.RPCWrapper
	secret            string
	pingReportChannel string
	stop              chan bool
}

// NewPingReportClient initializes a new ping report client
func NewPingReportClient(cr statscollector.Collector) (PingReportClient, error) {

	p := &pingReportClient{
		collector:         cr,
		rpchdl:            rpcwrapper.NewRPCWrapper(),
		secret:            os.Getenv(constants.EnvStatsSecret),
		pingReportChannel: os.Getenv(constants.EnvStatsChannel),
		stop:              make(chan bool),
	}

	if p.pingReportChannel == "" {
		return nil, errors.New("no path to stats socket provided")
	}

	if p.secret == "" {
		return nil, errors.New("no secret provided for stats channel")
	}

	return p, nil
}

func (p *pingReportClient) sendStats(ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			return
		case r := <-p.collector.GetPingReports():
			p.sendRequest(r)
		}
	}
}

func (p *pingReportClient) sendRequest(report *collector.PingReport) {

	request := rpcwrapper.Request{
		Payload: &rpcwrapper.PingReportPayload{
			Report: report,
		},
	}

	if err := p.rpchdl.RemoteCall(
		pingReportContextID,
		pingRPCCommand,
		&request,
		&rpcwrapper.Response{},
	); err != nil {
		zap.L().Error("RPC failure in sending dns reports", zap.Error(err))
	}
}

// Start This is an private function called by the remoteenforcer to connect back
// to the controller over a stats channel
func (p *pingReportClient) Run(ctx context.Context) error {
	if err := p.rpchdl.NewRPCClient(pingReportContextID, p.pingReportChannel, p.secret); err != nil {
		zap.L().Error("Stats RPC client cannot connect", zap.Error(err))
		return err
	}

	go p.sendStats(ctx)

	return nil
}
