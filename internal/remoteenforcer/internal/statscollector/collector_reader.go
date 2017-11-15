package statscollector

import "github.com/aporeto-inc/trireme/collector"

// Count returns the current number of flows.
func (c *collectorImpl) Count() int {
	c.Lock()
	defer c.Unlock()

	return len(c.Flows)
}

// GetAllRecords should return all flow records stashed so far.
func (c *collectorImpl) GetAllRecords() map[string]*collector.FlowRecord {
	c.Lock()
	defer c.Unlock()

	if len(c.Flows) == 0 {
		return nil
	}

	retval := c.Flows
	c.Flows = make(map[string]*collector.FlowRecord)
	return retval
}
