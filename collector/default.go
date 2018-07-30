package collector

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

// CollectUserEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectUserEvent(record *UserRecord) {}
