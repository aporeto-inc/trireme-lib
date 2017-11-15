package statsclient

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/internal/remoteenforcer/internal/statscollector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
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

	statsChannel := os.Getenv(constants.AporetoEnvStatsChannel)
	if statsChannel == "" {
		return nil, fmt.Errorf("No path to stats socket provided")
	}

	secret := os.Getenv(constants.AporetoEnvStatsSecret)
	if secret == "" {
		return nil, fmt.Errorf("No secret provided for stats channel")
	}

	statsInterval := defaultStatsIntervalMiliseconds * time.Millisecond
	envstatsInterval, err := strconv.Atoi(os.Getenv("STATS_INTERVAL"))
	if err == nil && envstatsInterval != 0 {
		statsInterval = time.Duration(envstatsInterval) * time.Second
	}

	return &statsClient{
		collector:     cr,
		rpchdl:        rpcwrapper.NewRPCWrapper(),
		secret:        secret,
		statsChannel:  statsChannel,
		statsInterval: statsInterval,
		stop:          make(chan bool),
	}, nil
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
