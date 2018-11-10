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
	// ipcaches is map[prefixlength][prefix] -> array of entries indexed by port
	local  map[int]map[uint32][]*entry
	remote map[int]map[uint32][]*entry
	// hostcaches is map[host] -> array of entries indexed by port.
	remoteHosts map[string][]*entry
	localHosts  map[string][]*entry
	sync.RWMutex
}

// NewTable creates a new table
func NewTable() *ServiceCache {
	return &ServiceCache{
		local:       map[int]map[uint32][]*entry{},
		remote:      map[int]map[uint32][]*entry{},
		remoteHosts: map[string][]*entry{},
		localHosts:  map[string][]*entry{},
	}
}

// Add adds a service into the cache
func (s *ServiceCache) Add(e *common.Service, data interface{}, local bool) error {
	s.Lock()
	defer s.Unlock()

	if err := s.addHostService(e, data, local); err != nil {
		return err
	}

	return s.addIPService(e, data, local)
}

// Find searches for a matching service, given an IP and port
func (s *ServiceCache) Find(ip net.IP, port int, host string, local bool) interface{} {
	s.RLock()
	defer s.RUnlock()

	if host != "" {
		if data := s.findHost(host, port, local); data != nil {
			return data
		}
	}

	return s.findIP(ip, port, local)
}

func (s *ServiceCache) addIPService(e *common.Service, data interface{}, local bool) error {
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

func (s *ServiceCache) addHostService(e *common.Service, data interface{}, local bool) error {
	hostCache := s.remoteHosts
	if local {
		hostCache = s.localHosts
	}

	// If addresses are nil, I only care about ports.
	if len(e.FQDNs) == 0 {
		return nil
	}

	for _, host := range e.FQDNs {
		if _, ok := hostCache[host]; !ok {
			hostCache[host] = []*entry{}
		}
		for _, spec := range hostCache[host] {
			if spec.ports.Overlaps(e.Ports) {
				return fmt.Errorf("Service port overlap for a given host not allowed")
			}
		}
		hostCache[host] = append(hostCache[host], &entry{
			ports: e.Ports,
			data:  data,
		})
	}
	return nil
}

// findIP searches for a matching service, given an IP and port
func (s *ServiceCache) findIP(ip net.IP, port int, local bool) interface{} {
	prefixes := s.remote
	if local {
		prefixes = s.local
	}

	if ip == nil {
		return nil
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

// findIP searches for a matching service, given an IP and port
func (s *ServiceCache) findHost(host string, port int, local bool) interface{} {
	hostCache := s.remoteHosts
	if local {
		hostCache = s.localHosts
	}

	entries, ok := hostCache[host]
	if !ok {
		return nil
	}
	for _, e := range entries {
		if e.ports.IsIncluded(port) {
			return e.data
		}
	}

	return nil
}
