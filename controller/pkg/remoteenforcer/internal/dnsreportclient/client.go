package dnsreportclient

import (
	"context"
	"errors"
	"os"

	"go.aporeto.io/trireme-lib/v11/collector"
	"go.aporeto.io/trireme-lib/v11/controller/constants"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/remoteenforcer/internal/statscollector"
	"go.uber.org/zap"
)

const (
	dnsReportContextID = "UNUSED"
	dnsRPCCommand      = "ProxyRPCServer.DNSReports"
)

// dsnReportClient  This is the struct for storing state for the rpc client
// which reports dns requests back to the controller process
type dnsreportsClient struct {
	collector        statscollector.Collector
	rpchdl           *rpcwrapper.RPCWrapper
	secret           string
	dnsReportChannel string
	stop             chan bool
}

// NewDNSReportClient initializes a new dns report client
func NewDNSReportClient(cr statscollector.Collector) (DNSReportClient, error) {

	dc := &dnsreportsClient{
		collector:        cr,
		rpchdl:           rpcwrapper.NewRPCWrapper(),
		secret:           os.Getenv(constants.EnvStatsSecret),
		dnsReportChannel: os.Getenv(constants.EnvStatsChannel),
		stop:             make(chan bool),
	}

	if dc.dnsReportChannel == "" {
		return nil, errors.New("no path to stats socket provided")
	}

	if dc.secret == "" {
		return nil, errors.New("no secret provided for stats channel")
	}

	return dc, nil
}

func (d *dnsreportsClient) sendStats(ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			return
		case rep := <-d.collector.GetDNSReports():
			d.sendRequest(rep)
		}
	}
}

func (d *dnsreportsClient) sendRequest(dnsreport *collector.DNSRequestReport) {

	request := rpcwrapper.Request{
		Payload: &rpcwrapper.DNSReportPayload{
			Report: dnsreport,
		},
	}

	if err := d.rpchdl.RemoteCall(
		dnsReportContextID,
		dnsRPCCommand,
		&request,
		&rpcwrapper.Response{},
	); err != nil {
		zap.L().Error("RPC failure in sending dns reports", zap.Error(err))
	}
}

// Start This is an private function called by the remoteenforcer to connect back
// to the controller over a stats channel
func (d *dnsreportsClient) Run(ctx context.Context) error {
	if err := d.rpchdl.NewRPCClient(dnsReportContextID, d.dnsReportChannel, d.secret); err != nil {
		zap.L().Error("Stats RPC client cannot connect", zap.Error(err))
		return err
	}

	go d.sendStats(ctx)

	return nil
}
