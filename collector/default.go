package collector

import "github.com/aporeto-inc/trireme/enforcer/packet"

// DefaultCollector implements a default collector infrastructure to syslog
type DefaultCollector struct{}

// CollectFlowEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectFlowEvent(contextID string, labels map[string]string, action string, mode string, sourceID string, tcpPacket *packet.Packet) {
	return
}

// CollectContainerEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectContainerEvent(contextID string, ip string, labels map[string]string, event string) {
	return
}
