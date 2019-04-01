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
	id    string
	ports *portspec.PortSpec
	data  interface{}
}

type entryList []*entry

func (e entryList) Delete(i int) entryList {
	if i >= len(e) || i < 0 {
		return e
	}
	return append(e[:i], e[i+1:]...)
}

// ServiceCache is a new service cache
type ServiceCache struct {
	// ipcaches is map[prefixlength][prefix] -> array of entries indexed by port
	local  map[int]map[uint32]entryList
	remote map[int]map[uint32]entryList
	// hostcaches is map[host] -> array of entries indexed by port.
	remoteHosts map[string]entryList
	localHosts  map[string]entryList
	// portCaches is list of all ports where we can retrieve a service based on the port.
	remotePorts entryList
	localPorts  entryList
	sync.RWMutex
}

// NewTable creates a new table
func NewTable() *ServiceCache {
	return &ServiceCache{
		local:       map[int]map[uint32]entryList{},
		remote:      map[int]map[uint32]entryList{},
		remoteHosts: map[string]entryList{},
		localHosts:  map[string]entryList{},
	}
}

// Add adds a service into the cache. Returns error of if any overlap has been detected.
func (s *ServiceCache) Add(e *common.Service, id string, data interface{}, local bool) error {
	s.Lock()
	defer s.Unlock()

	record := &entry{
		ports: e.Ports,
		data:  data,
		id:    id,
	}
	if err := s.addPorts(e, record, local); err != nil {
		return err
	}

	if err := s.addHostService(e, record, local); err != nil {
		return err
	}

	return s.addIPService(e, record, local)
}

// Find searches for a matching service, given an IP and port. Caller must specify
// the local or remote context.
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

// FindListeningServicesForPU returns a service that is found and the associated
// portSpecifications that refer to this service.
func (s *ServiceCache) FindListeningServicesForPU(id string) (interface{}, *portspec.PortSpec) {
	s.RLock()
	defer s.RUnlock()

	for _, spec := range s.localPorts {
		if spec.id == id {
			return spec.data, spec.ports
		}
	}
	return nil, nil
}

// DeleteByID will delete all entries related to this ID from all references.
func (s *ServiceCache) DeleteByID(id string, local bool) {
	s.Lock()
	defer s.Unlock()

	hosts := s.remoteHosts
	prefixes := s.remote
	if local {
		hosts = s.localHosts
		prefixes = s.local
	}

	if local {
		s.localPorts = deleteMatchingPorts(s.localPorts, id)
	} else {
		s.remotePorts = deleteMatchingPorts(s.remotePorts, id)
	}

	for host, ports := range hosts {
		hosts[host] = deleteMatchingPorts(ports, id)
		if len(hosts[host]) == 0 {
			delete(hosts, host)
		}
	}

	for l, prefix := range prefixes {
		for ip, ports := range prefix {
			prefix[ip] = deleteMatchingPorts(ports, id)
			if len(prefix[ip]) == 0 {
				delete(prefix, ip)
			}
		}
		if len(prefix) == 0 {
			delete(prefixes, l)
		}
	}
}

func deleteMatchingPorts(list entryList, id string) entryList {
	remainingPorts := entryList{}
	for _, spec := range list {
		if spec.id != id {
			remainingPorts = append(remainingPorts, spec)
		}
	}
	return remainingPorts
}

func (s *ServiceCache) addIPService(e *common.Service, record *entry, local bool) error {
	prefixes := s.remote
	if local {
		prefixes = s.local
	}

	addresses := e.Addresses
	// If addresses are nil, I only care about ports.
	if len(e.Addresses) == 0 {
		_, ip, _ := net.ParseCIDR("0.0.0.0/0")
		addresses = append(addresses, ip)
	}

	for _, addr := range addresses {
		binPrefix := binary.BigEndian.Uint32(addr.IP) & binary.BigEndian.Uint32(addr.Mask)
		len, _ := addr.Mask.Size()
		if _, ok := prefixes[len]; !ok {
			prefixes[len] = map[uint32]entryList{}
		}
		if _, ok := prefixes[len][binPrefix]; !ok {
			prefixes[len][binPrefix] = entryList{}
		}
		for _, spec := range prefixes[len][binPrefix] {
			if spec.ports.Overlaps(e.Ports) {
				return fmt.Errorf("service port overlap for a given IP not allowed: ip %s, port %s", addr.String(), e.Ports.String())
			}
		}
		prefixes[len][binPrefix] = append(prefixes[len][binPrefix], record)
	}
	return nil
}

func (s *ServiceCache) addHostService(e *common.Service, record *entry, local bool) error {
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
			hostCache[host] = entryList{}
		}
		for _, spec := range hostCache[host] {
			if spec.ports.Overlaps(e.Ports) {
				return fmt.Errorf("service port overlap for a given host not allowed: host %s, port %s", host, e.Ports.String())
			}
		}
		hostCache[host] = append(hostCache[host], record)
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

		binPrefix := binary.BigEndian.Uint32(ip.To4()) & binary.BigEndian.Uint32(net.CIDRMask(len, 32))
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

// addPorts will only work for local ports.
func (s *ServiceCache) addPorts(e *common.Service, record *entry, local bool) error {
	if !local {
		return nil
	}

	for _, spec := range s.localPorts {
		if spec.ports.Overlaps(e.Ports) {
			return fmt.Errorf("service port overlap in the global port list: %+v %s", e.Addresses, e.Ports.String())
		}
	}

	s.localPorts = append(s.localPorts, record)

	return nil
}
