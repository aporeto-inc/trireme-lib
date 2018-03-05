package collector

import (
	"encoding/binary"
	"fmt"

	"github.com/cespare/xxhash"
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

// StatsFlowHash is a hash function to hash flows
func StatsFlowHash(r *FlowRecord) string {
	hash := xxhash.New()
	hash.Write([]byte(r.Source.ID))      // nolint errcheck
	hash.Write([]byte(r.Destination.ID)) // nolint errcheck
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, r.Destination.Port)
	hash.Write(port)                      // nolint errcheck
	hash.Write([]byte(r.Action.String())) // nolint errcheck
	hash.Write([]byte(r.DropReason))      // nolint errcheck
	hash.Write([]byte(r.Destination.URI)) // nolint errcheck

	return fmt.Sprintf("%d", hash.Sum64())
}

// StatsUserHash is a hash function to hash user records
func StatsUserHash(r *UserRecord) error {
	hash := xxhash.New()
	for _, claim := range r.Claims {
		if _, err := hash.Write([]byte(claim)); err != nil {
			return fmt.Errorf("Cannot create hash")
		}
	}
	r.ID = fmt.Sprintf("%d", hash.Sum64())
	return nil
}
