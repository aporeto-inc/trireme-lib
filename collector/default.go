package collector

import (
	"fmt"
	"strconv"
)

// DefaultCollector implements a default collector infrastructure to syslog
type DefaultCollector struct{}

// CollectFlowEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectFlowEvent(r *FlowRecord) {
	return
}

// CollectContainerEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectContainerEvent(r *ContainerRecord) {
	fmt.Printf("Container Event: %+v", *r)
	return
}

// StatsFlowHash is a has function to hash flows
func StatsFlowHash(r *FlowRecord) string {
	fmt.Printf("Flow Event: %+v", *r)
	return r.SourceID + ":" + r.DestinationID + ":" + strconv.Itoa(int(r.DestinationPort)) + ":" + r.Action + ":" + r.Mode
}
