package portcache

import (
	"fmt"

	"github.com/ericrpowers/go-deadlock"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.aporeto.io/trireme-lib/utils/portspec"
)

// PortCache is a generic cache of port pairs or exact ports. It can store
// and do lookups of ports on exact matches or ranges. It returns the stored
// values
type PortCache struct {
	ports  cache.DataStore
	ranges []*portspec.PortSpec
	deadlock.Mutex
}

// NewPortCache creates a new port cache
func NewPortCache(name string) *PortCache {
	return &PortCache{
		ports:  cache.NewCache(name),
		ranges: []*portspec.PortSpec{},
	}
}

// AddPortSpec adds a port spec into the cache
func (p *PortCache) AddPortSpec(s *portspec.PortSpec) {
	if s.Min == s.Max {
		p.ports.AddOrUpdate(s.Min, s)
	} else {
		// Remove the range if it exists
		p.Remove(s) // nolint
		// Insert the portspec
		p.Lock()
		p.ranges = append([]*portspec.PortSpec{s}, p.ranges...)
		p.Unlock()
	}
}

// AddPortSpecToEnd adds a range at the end of the cache
func (p *PortCache) AddPortSpecToEnd(s *portspec.PortSpec) {

	// Remove the range if it exists
	p.Remove(s) // nolint

	p.Lock()
	p.ranges = append(p.ranges, s)
	p.Unlock()

}

// AddUnique adds a port spec into the cache and makes sure its unique
func (p *PortCache) AddUnique(s *portspec.PortSpec) error {
	p.Lock()
	defer p.Unlock()

	if s.Min == s.Max {
		if err, _ := p.ports.Get(s.Min); err != nil {
			return fmt.Errorf("Port already exists: %s", err)
		}
	}

	for _, r := range p.ranges {
		if r.Max <= s.Min || r.Min >= s.Max {
			continue
		}
		return fmt.Errorf("Overlap detected: %d %d", r.Max, r.Min)
	}

	if s.Min == s.Max {
		return p.ports.Add(s.Min, s)
	}

	p.ranges = append(p.ranges, s)
	return nil
}

// GetSpecValueFromPort searches the cache for a match based on a port
// It will return the first match found on exact ports or on the ranges
// of ports. If there are multiple intervals that match it will randomly
// return one of them.
func (p *PortCache) GetSpecValueFromPort(port uint16) (interface{}, error) {
	if spec, err := p.ports.Get(port); err == nil {
		return spec.(*portspec.PortSpec).Value(), nil
	}

	p.Lock()
	defer p.Unlock()
	for _, s := range p.ranges {
		if s.Min <= port && port < s.Max {
			return s.Value(), nil
		}
	}

	return nil, fmt.Errorf("No match for port %d", port)
}

// GetAllSpecValueFromPort will return all the specs that potentially match. This
// will allow for overlapping ranges
func (p *PortCache) GetAllSpecValueFromPort(port uint16) ([]interface{}, error) {
	var allMatches []interface{}

	if spec, err := p.ports.Get(port); err == nil {
		allMatches = append(allMatches, spec.(*portspec.PortSpec).Value())
	}

	p.Lock()
	defer p.Unlock()
	for _, s := range p.ranges {
		if s.Min <= port && port < s.Max {
			allMatches = append(allMatches, s.Value())
		}
	}

	if len(allMatches) == 0 {
		return nil, fmt.Errorf("No match for port %d", port)
	}
	return allMatches, nil
}

// Remove will remove a port from the cache
func (p *PortCache) Remove(s *portspec.PortSpec) error {

	if s.Min == s.Max {
		return p.ports.Remove(s.Min)
	}

	p.Lock()
	defer p.Unlock()
	for i, r := range p.ranges {
		if r.Min == s.Min && r.Max == s.Max {
			left := p.ranges[:i]
			right := p.ranges[i+1:]
			p.ranges = append(left, right...)
			return nil
		}
	}

	return fmt.Errorf("port not found")
}

// RemoveStringPorts will remove a port from the cache
func (p *PortCache) RemoveStringPorts(ports string) error {

	s, err := portspec.NewPortSpecFromString(ports, nil)
	if err != nil {
		return err
	}

	return p.Remove(s)
}
