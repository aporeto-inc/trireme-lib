package statscollector

import (
	"github.com/aporeto-inc/trireme-lib/collector"
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
