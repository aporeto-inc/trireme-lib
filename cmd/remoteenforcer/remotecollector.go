package remoteenforcer

import (
	"sync"

	"github.com/aporeto-inc/trireme/collector"
)

// CollectorImpl : This is a local implementation for the collector interface
// It has a flow entries cache which contains unique flows that are reported back to the
// controller/launcher process
type CollectorImpl struct {
	Flows map[string]*collector.FlowRecord
	sync.Mutex
}

// NewCollector creates a new remote collector for statistics
func NewCollector() *CollectorImpl {
	return &CollectorImpl{
		Flows: map[string]*collector.FlowRecord{},
	}
}

// CollectFlowEvent collects a new flow event and adds it to a local list it shares with SendStats
func (c *CollectorImpl) CollectFlowEvent(record *collector.FlowRecord) {

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

	c.Flows[hash].Tags = c.Flows[hash].Tags.Clone()
}

//CollectContainerEvent exported
//This event should not be expected here in the enforcer process inside a particular container context
func (c *CollectorImpl) CollectContainerEvent(record *collector.ContainerRecord) {
	return
}
