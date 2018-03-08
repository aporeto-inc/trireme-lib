package statscollector

import (
	"github.com/aporeto-inc/trireme-lib/collector"
)

// CollectorReader interface which provides functions to query pending stats
type CollectorReader interface {
	Count() int
	GetAllRecords() map[string]*collector.FlowRecord
	GetUserRecords() map[string]*collector.UserRecord
	FlushUserCache()
}

// Collector interface implements
type Collector interface {
	CollectorReader
	collector.EventCollector
}
