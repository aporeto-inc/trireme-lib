package statscollector

import (
	"go.aporeto.io/enforcerd/trireme-lib/collector"
)

// CollectorReader interface which provides functions to query pending stats.
type CollectorReader interface {
	Count() int
	FlushUserCache()
	GetFlowRecords() map[uint64]*collector.FlowRecord
	GetUserRecords() map[string]*collector.UserRecord
	GetReports() chan *Report
}

// Collector interface implements event collector.
type Collector interface {
	CollectorReader
	collector.EventCollector
}
