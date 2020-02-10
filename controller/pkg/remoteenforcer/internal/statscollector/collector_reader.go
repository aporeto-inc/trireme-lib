package statscollector

import (
	"go.aporeto.io/trireme-lib/v11/collector"
)

// Count returns the current number of records collected.
func (c *collectorImpl) Count() int {
	c.Lock()
	defer c.Unlock()

	return len(c.Flows)
}

// GetFlowRecords should return all flow records stashed so far.
func (c *collectorImpl) GetFlowRecords() map[string]*collector.FlowRecord {
	c.Lock()
	defer c.Unlock()

	if len(c.Flows) == 0 {
		return nil
	}

	retval := c.Flows
	c.Flows = make(map[string]*collector.FlowRecord)
	return retval
}

// GetUserRecords retrieves all the user records.
func (c *collectorImpl) GetUserRecords() map[string]*collector.UserRecord {
	c.Lock()
	defer c.Unlock()

	if len(c.Users) == 0 {
		return nil
	}

	retval := c.Users
	c.Users = map[string]*collector.UserRecord{}
	return retval
}

// FlushUserCache flushes the user cache.
func (c *collectorImpl) FlushUserCache() {
	c.Lock()
	defer c.Unlock()

	c.ProcessedUsers = map[string]bool{}
}

// GetReports returns reports channel.
func (c *collectorImpl) GetReports() chan *Report {
	c.Lock()
	defer c.Unlock()

	return c.Reports
}
