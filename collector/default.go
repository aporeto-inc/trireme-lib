package collector

import (
	"fmt"

	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/policy"
)

// DefaultCollector implements a default collector infrastructure to syslog
type DefaultCollector struct{}

// CollectFlowEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectFlowEvent(contextID string, tags *policy.TagsMap, action string, mode string, sourceID string, tcpPacket *packet.Packet) {
	fmt.Printf("Collected Flow from srcip %s to dstip %s\n", tcpPacket.SourceAddress.String(), tcpPacket.DestinationAddress.String())
	return
}

// CollectContainerEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectContainerEvent(contextID string, ip string, tags *policy.TagsMap, event string) {
	return
}
