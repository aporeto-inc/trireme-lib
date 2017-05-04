package remoteenforcer

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
)

const (
	defaultStatsIntervalMiliseconds = 1000
	envStatsChannelPath             = "STATSCHANNEL_PATH"
	envStatsSecret                  = "STATS_SECRET"
	statsContextID                  = "UNUSED"
	statsRPCCommand                 = "StatsServer.GetStats"
)

//StatsClient  This is the struct for storing state for the rpc client
//which reports flow stats back to the controller process
type StatsClient struct {
	collector     *CollectorImpl
	rpchdl        *rpcwrapper.RPCWrapper
	secret        string
	statsChannel  string
	statsInterval time.Duration
	stop          chan bool
}

// NewStatsClient initializes a new stats client
func NewStatsClient() (*StatsClient, error) {

	statsChannel := os.Getenv(envStatsChannelPath)
	if len(statsChannel) == 0 {
		return nil, fmt.Errorf("No path to stats socket provided")
	}

	secret := os.Getenv(envStatsSecret)
	if len(secret) == 0 {
		return nil, fmt.Errorf("No secret provided for stats channel")
	}

	statsInterval := defaultStatsIntervalMiliseconds * time.Millisecond
	envstatsInterval, err := strconv.Atoi(os.Getenv("STATS_INTERVAL"))
	if err == nil && envstatsInterval != 0 {
		statsInterval = time.Duration(envstatsInterval) * time.Second
	}

	return &StatsClient{
		collector:     NewCollector(),
		rpchdl:        rpcwrapper.NewRPCWrapper(),
		secret:        secret,
		statsChannel:  statsChannel,
		statsInterval: statsInterval,
		stop:          make(chan bool),
	}, nil
}

//SendStats  async function which makes a rpc call to send stats every STATS_INTERVAL
func (s *StatsClient) SendStats() {

	ticker := time.NewTicker(s.statsInterval)
	// nolint : gosimple
	for {
		select {
		case <-ticker.C:

			s.collector.Lock()
			if len(s.collector.Flows) == 0 {
				s.collector.Unlock()
				break
			}
			collected := s.collector.Flows
			s.collector.Flows = map[string]*collector.FlowRecord{}
			s.collector.Unlock()

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

// connectStatsCLient  This is an private function called by the remoteenforcer to connect back
// to the controller over a stats channel
func (s *StatsClient) connectStatsClient() error {

	if err := s.rpchdl.NewRPCClient(statsContextID, s.statsChannel, s.secret); err != nil {
		zap.L().Error("Stats RPC client cannot connect", zap.Error(err))
		return err
	}

	go s.SendStats()

	return nil
}

// Stop stops the stats client at clean up
func (s *StatsClient) Stop() {

	s.stop <- true

	zap.L().Debug("Stopping stats collector")
}
