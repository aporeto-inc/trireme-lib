package servicecache

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/utils/portspec"
)

type entry struct {
	ports *portspec.PortSpec
	data  interface{}
}

// ServiceCache is a new service cache
type ServiceCache struct {
	prefixes map[int]map[uint32][]*entry
	sync.RWMutex
}

// NewTable creates a new table
func NewTable() *ServiceCache {
	return &ServiceCache{
		prefixes: map[int]map[uint32][]*entry{},
	}
}

// Add adds a service into the cache
func (s *ServiceCache) Add(e *common.Service, data interface{}) error {
	s.Lock()
	defer s.Unlock()
	for _, addr := range e.Addresses {
		binPrefix := binary.BigEndian.Uint32(addr.IP) & binary.BigEndian.Uint32(addr.Mask)
		len, _ := addr.Mask.Size()
		if _, ok := s.prefixes[len]; !ok {
			s.prefixes[len] = map[uint32][]*entry{}
		}
		if _, ok := s.prefixes[len][binPrefix]; !ok {
			s.prefixes[len][binPrefix] = []*entry{}
		}
		for _, spec := range s.prefixes[len][binPrefix] {
			if spec.ports.Overlaps(e.Ports) {
				return fmt.Errorf("Service port overlap for a given IP not allowed")
			}
		}
		s.prefixes[len][binPrefix] = append(s.prefixes[len][binPrefix], &entry{
			ports: e.Ports,
			data:  data,
		})
	}
	return nil
}

// Find searches for a matching service, given an IP and port
func (s *ServiceCache) Find(ip net.IP, port int) interface{} {
	s.RLock()
	defer s.RUnlock()
	for len, prefix := range s.prefixes {
		binPrefix := binary.BigEndian.Uint32(ip) & binary.BigEndian.Uint32(net.CIDRMask(len, 32))
		entries, ok := prefix[binPrefix]
		if !ok {
			continue
		}

		for _, e := range entries {
			if e.ports.IsIncluded(port) {
				return e.data
			}
		}
	}
	return nil
}
