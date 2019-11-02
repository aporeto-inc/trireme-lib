package statscollector

import (
	"sync"

	"go.aporeto.io/trireme-lib/v11/collector"
)

// NewCollector provides a new collector interface
func NewCollector() Collector {
	return &collectorImpl{
		Flows:                 map[string]*collector.FlowRecord{},
		Users:                 map[string]*collector.UserRecord{},
		ProcessedUsers:        map[string]bool{},
		DatapathPacketReports: []*collector.PacketReport{},
		CounterReports:        []*collector.CounterReport{},
		DNSReport:             make(chan *collector.DNSRequestReport),
	}
}

// collectorImpl : This object is a stash implements two interfaces.
//
//  collector.EventCollector - so datapath can report flow events
//  CollectorReader - so components can extract information out of this stash
//
// It has a flow entries cache which contains unique flows that are reported
// back to the controller/launcher process
type collectorImpl struct {
	Flows                 map[string]*collector.FlowRecord
	ProcessedUsers        map[string]bool
	Users                 map[string]*collector.UserRecord
	DatapathPacketReports []*collector.PacketReport
	CounterReports        []*collector.CounterReport
	DNSReport             chan *collector.DNSRequestReport
	sync.Mutex
}
