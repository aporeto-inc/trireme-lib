package statscollector

import (
	"go.aporeto.io/trireme-lib/collector"
)

// CollectorReader interface which provides functions to query pending stats
type CollectorReader interface {
	Count() int
	GetAllRecords() map[string]*collector.FlowRecord
	GetUserRecords() map[string]*collector.UserRecord
	FlushUserCache()
	GetAllDataPathPacketRecords() []*collector.PacketReport
	GetAllCounterReports() []*collector.CounterReport
	GetDNSReports() chan *collector.DNSRequestReport
	GetPingReports() chan *collector.PingReport
}

// Collector interface implements
type Collector interface {
	CollectorReader
	collector.EventCollector
}
