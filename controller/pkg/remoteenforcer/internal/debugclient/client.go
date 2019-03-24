package debugclient

import (
	"context"
	"errors"
	"os"
	"time"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/statscollector"
	"go.uber.org/zap"
)

const (
	defaultDebugIntervalMilliseconds = 1000
	debugContextID                   = "UNUSED"
	debugRPCCommand                  = "StatsServer.PostPacketEvent"
)

type debugClient struct {
	collector     statscollector.Collector
	rpchdl        *rpcwrapper.RPCWrapper
	secret        string
	debugChannel  string
	debugInterval time.Duration
	stop          chan bool
}

// NewDebugClient initializes a new Debug Client
func NewDebugClient(cr statscollector.Collector) (DebugClient, error) {
	d := &debugClient{
		collector:     cr,
		rpchdl:        rpcwrapper.NewRPCWrapper(),
		secret:        os.Getenv(constants.EnvStatsSecret),
		debugChannel:  os.Getenv(constants.EnvStatsChannel),
		debugInterval: defaultDebugIntervalMilliseconds * time.Millisecond,
		stop:          make(chan bool),
	}

	if d.debugChannel == "" {
		return nil, errors.New("no path to debug socket provided")
	}

	if d.secret == "" {
		return nil, errors.New("no secret provided for debug channel")
	}

	return d, nil
}

func (d *debugClient) sendData(records []*collector.PacketReport) error {
	request := rpcwrapper.Request{
		Payload: &rpcwrapper.DebugPacketPayload{
			PacketRecords: records,
		},
	}
	return d.rpchdl.RemoteCall(
		debugContextID,
		debugRPCCommand,
		&request,
		&rpcwrapper.Response{},
	)
}

func (d *debugClient) sendPacketReports(ctx context.Context) {
	ticker := time.NewTicker(d.debugInterval)
	for {
		select {
		case <-ticker.C:
			records := d.collector.GetAllDataPathPacketRecords()
			if len(records) > 0 {
				if err := d.sendData(records); err != nil {
					zap.L().Debug("Unable to send debug packet reports", zap.Error(err))
				}
			}
		case <-ctx.Done():
			records := d.collector.GetAllDataPathPacketRecords()
			if err := d.sendData(records); err != nil {
				zap.L().Debug("Unable to send debug packet reports", zap.Error(err))
			}
			return
		}
	}

}
func (d *debugClient) Run(ctx context.Context) error {
	if err := d.rpchdl.NewRPCClient(debugContextID, d.debugChannel, d.secret); err != nil {
		zap.L().Error("Debug RPC client cannot connect", zap.Error(err))
		return err
	}
	go d.sendPacketReports(ctx)
	return nil
}
