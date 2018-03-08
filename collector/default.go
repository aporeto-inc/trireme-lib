package collector

import "strconv"

// DefaultCollector implements a default collector infrastructure to syslog
type DefaultCollector struct{}

// NewDefaultCollector returns a default implementation of an EventCollector
func NewDefaultCollector() EventCollector {
	return &DefaultCollector{}
}

// CollectFlowEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectFlowEvent(record *FlowRecord) {}

// CollectContainerEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectContainerEvent(record *ContainerRecord) {}

// StatsFlowHash is a has function to hash flows
func StatsFlowHash(r *FlowRecord) string {
	return r.Source.ID + ":" + r.Destination.ID + ":" + strconv.Itoa(int(r.Destination.Port)) + ":" + r.Action.String() + ":" + r.DropReason
}
