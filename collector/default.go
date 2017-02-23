package collector

import "strconv"

// DefaultCollector implements a default collector infrastructure to syslog
type DefaultCollector struct{}

// CollectFlowEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectFlowEvent(record *FlowRecord) {
	return
}

// CollectContainerEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectContainerEvent(record *ContainerRecord) {
	return
}

// StatsFlowHash is a has function to hash flows
func StatsFlowHash(r *FlowRecord) string {
	return r.SourceID + ":" + r.DestinationID + ":" + strconv.Itoa(int(r.DestinationPort)) + ":" + r.Action + ":" + r.Mode
}
