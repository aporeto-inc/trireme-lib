package statsclient

import (
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme-lib/internal/remoteenforcer/internal/statscollector"
)

const (
	defaultStatsIntervalMiliseconds = 1000
	statsContextID                  = "UNUSED"
	statsRPCCommand                 = "StatsServer.GetStats"
)

// statsClient  This is the struct for storing state for the rpc client
// which reports flow stats back to the controller process
type statsClient struct {
	collector     statscollector.Collector
	rpchdl        *rpcwrapper.RPCWrapper
	secret        string
	statsChannel  string
	statsInterval time.Duration
	stop          chan bool
}

// NewStatsClient initializes a new stats client
func NewStatsClient(cr statscollector.Collector) (StatsClient, error) {

	sc := &statsClient{
		collector:     cr,
		rpchdl:        rpcwrapper.NewRPCWrapper(),
		secret:        os.Getenv(constants.AporetoEnvStatsSecret),
		statsChannel:  os.Getenv(constants.AporetoEnvStatsChannel),
		statsInterval: defaultStatsIntervalMiliseconds * time.Millisecond,
		stop:          make(chan bool),
	}

	if sc.statsChannel == "" {
		return nil, fmt.Errorf("No path to stats socket provided")
	}

	if sc.secret == "" {
		return nil, fmt.Errorf("No secret provided for stats channel")
	}

	return sc, nil
}

// sendStats  async function which makes a rpc call to send stats every STATS_INTERVAL
func (s *statsClient) sendStats() {

	ticker := time.NewTicker(s.statsInterval)
	// nolint : gosimple
	for {
		select {
		case <-ticker.C:

			if s.collector.Count() == 0 {
				break
			}
			collected := s.collector.GetAllRecords()
			if len(collected) == 0 {
				continue
			}

			rpcPayload := &rpcwrapper.StatsPayload{
				Flows: collected,
			}

			request := rpcwrapper.Request{
				Payload: rpcPayload,
			}

			err := s.rpchdl.RemoteCall(
				statsContextID,
				statsRPCCommand,
				&request,
				&rpcwrapper.Response{},
			)

			if err != nil {
				zap.L().Error("RPC failure in sending statistics: Unable to send flows")
			}

		case <-s.stop:
			return
		}
	}

}

// Start This is an private function called by the remoteenforcer to connect back
// to the controller over a stats channel
func (s *statsClient) Start() error {

	if err := s.rpchdl.NewRPCClient(statsContextID, s.statsChannel, s.secret); err != nil {
		zap.L().Error("Stats RPC client cannot connect", zap.Error(err))
		return err
	}

	go s.sendStats()

	return nil
}

// Stop stops the stats client at clean up
func (s *statsClient) Stop() {

	s.stop <- true

	zap.L().Debug("Stopping stats collector")
}
