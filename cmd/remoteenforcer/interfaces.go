package remoteenforcer

//Stats interface which implements StatsClient struct
type Stats interface {
	SendStats()
	ConnectStatsClient() error
	Stop()
}
