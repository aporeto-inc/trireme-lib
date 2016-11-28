package collector

import (
<<<<<<< f904b9eb16171cdcc03b2c73dccb39ee8933dbfc
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
=======
	log "github.com/Sirupsen/logrus"
>>>>>>> Merged with mainline
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/utils/packet"
)

// DefaultCollector implements a default collector infrastructure to syslog
type DefaultCollector struct{}

// CollectFlowEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectFlowEvent(contextID string, tags policy.TagsMap, action string, mode string, sourceID string, tcpPacket *packet.Packet) {
	return
}

// CollectContainerEvent is part of the EventCollector interface.
func (d *DefaultCollector) CollectContainerEvent(contextID string, ip string, tags policy.TagsMap, event string) {
	return
}
