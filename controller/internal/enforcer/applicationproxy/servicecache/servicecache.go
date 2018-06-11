package servicecache

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/utils/portspec"
)

type entry struct {
	ports *portspec.PortSpec
	data  interface{}
}

// ServiceCache is a new service cache
type ServiceCache struct {
	local  map[int]map[uint32][]*entry
	remote map[int]map[uint32][]*entry
	sync.RWMutex
}

// NewTable creates a new table
func NewTable() *ServiceCache {
	return &ServiceCache{
		local:  map[int]map[uint32][]*entry{},
		remote: map[int]map[uint32][]*entry{},
	}
}

// Add adds a service into the cache
func (s *ServiceCache) Add(e *common.Service, data interface{}, local bool) error {
	s.Lock()
	defer s.Unlock()

	prefixes := s.remote
	if local {
		prefixes = s.local
	}

	// If addresses are nil, I only care about ports.
	if len(e.Addresses) == 0 {
		_, ip, _ := net.ParseCIDR("0.0.0.0/0")
		e.Addresses = []*net.IPNet{ip}
	}

	for _, addr := range e.Addresses {
		binPrefix := binary.BigEndian.Uint32(addr.IP) & binary.BigEndian.Uint32(addr.Mask)
		len, _ := addr.Mask.Size()
		if _, ok := prefixes[len]; !ok {
			prefixes[len] = map[uint32][]*entry{}
		}
		if _, ok := prefixes[len][binPrefix]; !ok {
			prefixes[len][binPrefix] = []*entry{}
		}
		for _, spec := range prefixes[len][binPrefix] {
			if spec.ports.Overlaps(e.Ports) {
				return fmt.Errorf("Service port overlap for a given IP not allowed")
			}
		}
		prefixes[len][binPrefix] = append(prefixes[len][binPrefix], &entry{
			ports: e.Ports,
			data:  data,
		})
	}
	return nil
}

// Find searches for a matching service, given an IP and port
func (s *ServiceCache) Find(ip net.IP, port int, local bool) interface{} {
	s.RLock()
	defer s.RUnlock()

	prefixes := s.remote
	if local {
		prefixes = s.local
	}

	for len, prefix := range prefixes {
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
