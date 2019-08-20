package counterclient

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
	counterContextID       = "UNUSED"
	counterRPCCommand      = "ProxyRPCServer.PostCounterEvent"
	defaultCounterInterval = 10000 * time.Millisecond
)

type counterClient struct {
	collector       statscollector.Collector
	rpchdl          rpcwrapper.RPCClient
	secret          string
	counterChannel  string
	counterInterval time.Duration
	stop            chan bool
}

// NewCounterClient returns an interface CounterClient
func NewCounterClient(cr statscollector.Collector) (CounterClient, error) {
	c := &counterClient{
		collector:       cr,
		rpchdl:          rpcwrapper.NewRPCWrapper(),
		secret:          os.Getenv(constants.EnvStatsSecret),
		counterChannel:  os.Getenv(constants.EnvStatsChannel),
		counterInterval: defaultCounterInterval,
		stop:            make(chan bool),
	}
	if c.counterChannel == "" {
		return nil, errors.New("no path to socket provided")
	}
	if c.secret == "" {
		return nil, errors.New("no secret provided for  channel")
	}

	return c, nil
}

func (c *counterClient) sendData(records []*collector.CounterReport) error {
	request := rpcwrapper.Request{
		Payload: &rpcwrapper.CounterReportPayload{
			CounterReports: records,
		},
	}

	return c.rpchdl.RemoteCall(
		counterContextID,
		counterRPCCommand,
		&request,
		&rpcwrapper.Response{},
	)
}
func (c *counterClient) sendCounterReports(ctx context.Context) {
	ticker := time.NewTicker(c.counterInterval)
	for {
		select {
		case <-ticker.C:
			records := c.collector.GetAllCounterReports()
			if len(records) > 0 {
				if err := c.sendData(records); err != nil {
					zap.L().Debug("Unable to send counter report", zap.Error(err))
				}
			}
		case <-ctx.Done():
			records := c.collector.GetAllCounterReports()
			if len(records) > 0 {
				if err := c.sendData(records); err != nil {
					zap.L().Debug("Unable to send counter report", zap.Error(err))
				}
			}
			return
		}
	}
}

// Run stats the counterClient
func (c *counterClient) Run(ctx context.Context) error {
	if err := c.rpchdl.NewRPCClient(counterContextID, c.counterChannel, c.secret); err != nil {
		zap.L().Error("CounterClient RPC client cannot connect", zap.Error(err))
		return err
	}

	go c.sendCounterReports(ctx)
	return nil

}
