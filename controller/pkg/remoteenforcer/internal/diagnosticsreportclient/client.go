package diagnosticsreportclient

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
	diagnosticsReportContextID = "UNUSED"
	diagnosticsRPCCommand      = "ProxyRPCServer.DiagnosticsEvent"
)

// dsnReportClient  This is the struct for storing state for the rpc client
// which reports dns requests back to the controller process
type diagnosticsReportClient struct {
	collector                statscollector.Collector
	rpchdl                   *rpcwrapper.RPCWrapper
	secret                   string
	diagnosticsReportChannel string
	stop                     chan bool
}

// NewDiagnosticsReportClient initializes a new dns report client
func NewDiagnosticsReportClient(cr statscollector.Collector) (DiagnosticsReportClient, error) {

	dc := &diagnosticsReportClient{
		collector:                cr,
		rpchdl:                   rpcwrapper.NewRPCWrapper(),
		secret:                   os.Getenv(constants.EnvStatsSecret),
		diagnosticsReportChannel: os.Getenv(constants.EnvStatsChannel),
		stop:                     make(chan bool),
	}

	if dc.diagnosticsReportChannel == "" {
		return nil, errors.New("no path to stats socket provided")
	}

	if dc.secret == "" {
		return nil, errors.New("no secret provided for stats channel")
	}

	return dc, nil
}

func (d *diagnosticsReportClient) sendStats(ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			return
		case r := <-d.collector.GetDiagnosticsReports():
			d.sendRequest(r)
		}
	}
}

func (d *diagnosticsReportClient) sendRequest(report *collector.DiagnosticsReport) {

	request := rpcwrapper.Request{
		Payload: &rpcwrapper.DiagnosticsReportPayload{
			Report: report,
		},
	}

	if err := d.rpchdl.RemoteCall(
		diagnosticsReportContextID,
		diagnosticsRPCCommand,
		&request,
		&rpcwrapper.Response{},
	); err != nil {
		zap.L().Error("RPC failure in sending dns reports", zap.Error(err))
	}
}

// Start This is an private function called by the remoteenforcer to connect back
// to the controller over a stats channel
func (d *diagnosticsReportClient) Run(ctx context.Context) error {
	if err := d.rpchdl.NewRPCClient(diagnosticsReportContextID, d.diagnosticsReportChannel, d.secret); err != nil {
		zap.L().Error("Stats RPC client cannot connect", zap.Error(err))
		return err
	}

	go d.sendStats(ctx)

	return nil
}
