package statscollector

import (
	"github.com/ericrpowers/go-deadlock"
	"go.aporeto.io/trireme-lib/collector"
)

// NewCollector provides a new collector interface
func NewCollector() Collector {
	return &collectorImpl{
		Flows:          map[string]*collector.FlowRecord{},
		Users:          map[string]*collector.UserRecord{},
		ProcessedUsers: map[string]bool{},
		Reports:        make(chan *Report, 1000),
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
	Flows          map[string]*collector.FlowRecord
	ProcessedUsers map[string]bool
	Users          map[string]*collector.UserRecord
	Reports        chan *Report

	deadlock.Mutex
}

// ReportType it the type of report.
type ReportType uint8

// ReportTypes.
const (
	FlowRecord ReportType = iota
	UserRecord
	PacketReport
	CounterReport
	DNSReport
	PingReport
)

// Report holds the report type and the payload.
type Report struct {
	Type    ReportType
	Payload interface{}
}
