package collector

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/cespare/xxhash"
	"go.aporeto.io/trireme-lib/policy"
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

// StatsFlowHash is a hash function to hash flows
func StatsFlowHash(r *FlowRecord) string {
	hash := xxhash.New()
	hash.Write([]byte(r.Source.ID))      // nolint errcheck
	hash.Write([]byte(r.Destination.ID)) // nolint errcheck
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, r.Destination.Port)
	hash.Write(port)                              // nolint errcheck
	hash.Write([]byte(r.Action.String()))         // nolint errcheck
	hash.Write([]byte(r.ObservedAction.String())) // nolint errcheck
	hash.Write([]byte(r.DropReason))              // nolint errcheck
	hash.Write([]byte(r.Destination.URI))         // nolint errcheck

	return fmt.Sprintf("%d", hash.Sum64())
}

// StatsUserHash is a hash function to hash user records.
func StatsUserHash(r *UserRecord) error {
	// Order matters for the hash function loop
	sort.Strings(r.Claims)
	hash := xxhash.New()
	for i := 0; i < len(r.Claims); i++ {
		if strings.HasPrefix(r.Claims[i], "sub") {
			continue
		}
		if _, err := hash.Write([]byte(r.Claims[i])); err != nil {
			return fmt.Errorf("unable to create hash: %v", err)
		}
	}

	hashWithNS, err := policy.XXHash(fmt.Sprintf("%d", hash.Sum64()), r.Namespace)
	if err != nil {
		return err
	}

	r.ID = hashWithNS

	return nil
}
