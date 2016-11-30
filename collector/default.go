package collector

import (
	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/policy"
)

// DefaultCollector implements a default collector infrastructure to syslog
type DefaultCollector struct{}

// CollectFlowEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectFlowEvent(contextID string, tags policy.TagsMap, action string, mode string, sourceID string, tcpPacket *packet.Packet) {
	log.WithFields(log.Fields{
		"package": "collector",
	}).Warn("You need to implement your own CollectFlowEvent")
	return
}

// CollectContainerEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectContainerEvent(contextID string, ip string, tags policy.TagsMap, event string) {
	log.WithFields(log.Fields{
		"package": "collector",
	}).Warn("You need to implement your own CollectFlowEvent")
	return
}
