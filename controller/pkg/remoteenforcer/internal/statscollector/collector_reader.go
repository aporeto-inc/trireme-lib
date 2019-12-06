package statscollector

import (
	"go.aporeto.io/trireme-lib/collector"
)

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

// GetAllDataPathPacketRecords returns all datapath packet tracing records
func (c *collectorImpl) GetAllDataPathPacketRecords() []*collector.PacketReport {
	c.Lock()
	defer c.Unlock()

	record := c.DatapathPacketReports
	c.DatapathPacketReports = []*collector.PacketReport{}
	return record
}

func (c *collectorImpl) GetAllCounterReports() []*collector.CounterReport {
	c.Lock()
	defer c.Unlock()

	records := c.CounterReports
	c.CounterReports = []*collector.CounterReport{}
	return records
}

func (c *collectorImpl) GetDNSReports() chan *collector.DNSRequestReport {
	return c.DNSReport
}

func (c *collectorImpl) GetDiagnosticsReports() chan *collector.DiagnosticsReport {
	return c.DiagnosticsReport
}
