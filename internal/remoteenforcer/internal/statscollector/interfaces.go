package statscollector

import (
	"github.com/aporeto-inc/trireme/collector"
)

// CollectorReader interface which provides functions to query pending stats
type CollectorReader interface {
	Count() int
	GetAllRecords() map[string]*collector.FlowRecord
}

// Collector interface implements
type Collector interface {
	CollectorReader
	collector.EventCollector
}
