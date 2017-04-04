package remoteenforcer

import (
	"os"
	"strconv"
	"time"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"

	log "github.com/Sirupsen/logrus"
)

const (
	defaultStatsIntervalMiliseconds = 250
	envStatsChannelPath             = "STATSCHANNEL_PATH"
	envStatsSecret                  = "STATS_SECRET"
	statsContextID                  = "UNUSED"
)

//StatsClient  This is the struct for storing state for the rpc client
//which reports flow stats back to the controller process
type StatsClient struct {
	collector *CollectorImpl
	Rpchdl    *rpcwrapper.RPCWrapper
}

//SendStats  async function which makes a rpc call to send stats every STATS_INTERVAL
func (s *StatsClient) SendStats() {

	EnvstatsInterval, err := strconv.Atoi(os.Getenv("STATS_INTERVAL"))

	statsInterval := defaultStatsIntervalMiliseconds * time.Millisecond
	if err == nil && EnvstatsInterval != 0 {
		statsInterval = time.Duration(EnvstatsInterval) * time.Second
	}

	ticker := time.NewTicker(statsInterval)

	for {
		select {
		case <-ticker.C:

			s.collector.Lock()
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

			err := s.Rpchdl.RemoteCall(
				statsContextID,
				"StatsServer.GetStats",
				&request,
				&rpcwrapper.Response{},
			)

			if err != nil {
				log.WithFields(log.Fields{
					"package": "remoteEnforcer",
					"Msg":     "Unable to send flows",
				}).Error("RPC failure in sending statistics")
			}

		}
	}

}

//connectStatsCLient  This is an private function called by the remoteenforcer to connect back
//to the controller over a stats channel
func (s *Server) connectStatsClient(statsClient *StatsClient) error {

	statsChannel := os.Getenv(envStatsChannelPath)
	secret := os.Getenv(envStatsSecret)
	err := statsClient.Rpchdl.NewRPCClient(statsContextID, statsChannel, secret)
	if err != nil {
		log.WithFields(log.Fields{"package": "remote_enforcer",
			"error": err.Error(),
		}).Error("Stats RPC client cannot connect")
	}
	_, err = statsClient.Rpchdl.GetRPCClient(statsContextID)

	go statsClient.SendStats()
	return err
}
