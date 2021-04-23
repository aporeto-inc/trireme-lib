package collector

import (
	"encoding/binary"

	"github.com/cespare/xxhash"
	"go.aporeto.io/underwater/core/policy/services"
)

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

// CollectTraceEvent collects iptables trace events
func (d *DefaultCollector) CollectTraceEvent(records []string) {}

// CollectPacketEvent collects packet events from the datapath
func (d *DefaultCollector) CollectPacketEvent(report *PacketReport) {}

// CollectCounterEvent collect counters from the datapath
func (d *DefaultCollector) CollectCounterEvent(report *CounterReport) {}

// CollectDNSRequests collect counters from the datapath
func (d *DefaultCollector) CollectDNSRequests(report *DNSRequestReport) {}

// CollectPingEvent collects ping events from the datapath
func (d *DefaultCollector) CollectPingEvent(report *PingReport) {}

// CollectConnectionExceptionReport collects the connection exception report
func (d *DefaultCollector) CollectConnectionExceptionReport(report *ConnectionExceptionReport) {}

// StatsFlowHash is a hash function to hash flows. Ignores source ports. Returns two hashes
// flowhash - minimal with SIP/DIP/Dport
// contenthash - hash with all contents to compare quickly and report when changes are observed
func StatsFlowHash(r *FlowRecord) (flowhash, contenthash uint64) {

	hash := xxhash.New()
	hash.Write([]byte(r.Source.ID))       // nolint errcheck
	hash.Write([]byte(r.Destination.ID))  // nolint errcheck
	hash.Write([]byte(r.Destination.URI)) // nolint errcheck
	hash.Write([]byte(r.Source.IP))       // nolint errcheck
	hash.Write([]byte(r.Destination.IP))  // nolint errcheck
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, r.Destination.Port)
	hash.Write(port) // nolint errcheck
	flowhash = hash.Sum64()

	hash.Write([]byte(r.Action.String()))         // nolint errcheck
	hash.Write([]byte(r.ObservedAction.String())) // nolint errcheck
	hash.Write([]byte(r.DropReason))              // nolint errcheck
	hash.Write([]byte(r.PolicyID))                // nolint errcheck
	return flowhash, hash.Sum64()
}

// StatsFlowContentHash is a hash function to hash flows. Ignores source ports. Returns
// contenthash - hash with all contents to compare quickly and report when changes are observed
func StatsFlowContentHash(r *FlowRecord) (contenthash uint64) {

	_, contenthash = StatsFlowHash(r)
	return contenthash
}

// StatsUserHash is a hash function to hash user records.
func StatsUserHash(r *UserRecord) error {
	hash, err := services.HashClaims(r.Claims, r.Namespace)
	if err != nil {
		return err
	}
	r.ID = hash
	return nil
}

// ConnectionExceptionReportHash is a hash function to hash connection exception reports.
func ConnectionExceptionReportHash(r *ConnectionExceptionReport) uint64 {

	hash := xxhash.New()
	hash.Write([]byte(r.PUID))          // nolint errcheck
	hash.Write([]byte(r.SourceIP))      // nolint errcheck
	hash.Write([]byte(r.DestinationIP)) // nolint errcheck
	hash.Write([]byte(r.Reason))        // nolint errcheck
	hash.Write([]byte(r.State))         // nolint errcheck
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, r.DestinationPort)
	hash.Write(port) // nolint errcheck

	return hash.Sum64()
}
