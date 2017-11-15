package statsclient

// StatsClient interface provides functions to start/stop a stats client
// A stats client is an active component which is responsible for collecting
// stats events stored by datapath and ship them to the master enforcer.
type StatsClient interface {
	Start() error
	Stop()
}
