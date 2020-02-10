package statscollector

import (
	"go.aporeto.io/trireme-lib/v11/collector"
)

// CollectorReader interface which provides functions to query pending stats.
type CollectorReader interface {
	Count() int
	FlushUserCache()
	GetFlowRecords() map[string]*collector.FlowRecord
	GetUserRecords() map[string]*collector.UserRecord
	GetReports() chan *Report
}

// Collector interface implements event collector.
type Collector interface {
	CollectorReader
	collector.EventCollector
}
