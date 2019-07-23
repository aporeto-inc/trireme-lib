package statscollector

import (
	"go.aporeto.io/trireme-lib/collector"
	"go.uber.org/zap"
)

// CollectFlowEvent collects a new flow event and adds it to a local list it shares with SendStats
func (c *collectorImpl) CollectFlowEvent(record *collector.FlowRecord) {

	hash := collector.StatsFlowHash(record)

	// If flow event doesn't have a count make it equal to 1. At least one flow is collected
	if record.Count == 0 {
		record.Count = 1
	}

	c.Lock()
	defer c.Unlock()

	if r, ok := c.Flows[hash]; ok {
		r.Count = r.Count + record.Count
		return
	}

	c.Flows[hash] = record

	c.Flows[hash].Tags = record.Tags
}

// CollectContainerEvent is called when container events are received
func (c *collectorImpl) CollectContainerEvent(record *collector.ContainerRecord) {
	zap.L().Error("Unexpected call for collecting container event")
}

// CollectUserEvent collects a new user event and adds it to a local cache.
func (c *collectorImpl) CollectUserEvent(record *collector.UserRecord) {
	if err := collector.StatsUserHash(record); err != nil {
		zap.L().Error("Cannot store user record", zap.Error(err))
		return
	}

	c.Lock()
	defer c.Unlock()

	if _, ok := c.ProcessedUsers[record.ID]; !ok {
		c.Users[record.ID] = record
		c.ProcessedUsers[record.ID] = true
	}
}

// CollectTraceEvent collect trace events
func (c *collectorImpl) CollectTraceEvent(records []string) {
	//We will leave this unimplemented
	// trace event collection in done from the main enforcer
}

// CollectTraceEvent collect trace events
func (c *collectorImpl) CollectPacketEvent(report *collector.PacketReport) {
	//We will leave this unimplemented
	// trace event collection in done from the main enforcer
	c.Lock()
	defer c.Unlock()
	zap.L().Debug("Collected Packet Event")
	c.DatapathPacketReports = append(c.DatapathPacketReports, report)

}

// CollectCounterEvent collect counters from the datapath
func (c *collectorImpl) CollectCounterEvent(report *collector.CounterReport) {
	c.Lock()
	defer c.Unlock()
	c.CounterReports = append(c.CounterReports, report)
}
