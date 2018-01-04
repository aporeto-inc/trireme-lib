package portcache

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aporeto-inc/trireme-lib/utils/cache"
)

// PortSpec is the specification of a port or port range
type PortSpec struct {
	Min   uint16
	Max   uint16
	value interface{}
}

// NewPortSpec creates a new port spec
func NewPortSpec(min, max uint16, value interface{}) (*PortSpec, error) {

	if min > max {
		return nil, errors.New("Min port greater than max")
	}

	return &PortSpec{
		Min:   min,
		Max:   max,
		value: value,
	}, nil
}

// NewPortSpecFromString creates a new port spec
func NewPortSpecFromString(ports string, value interface{}) (*PortSpec, error) {

	var min, max int
	var err error
	if strings.Contains(ports, ":") {
		portMinMax := strings.SplitN(ports, ":", 2)
		if len(portMinMax) != 2 {
			return nil, errors.New("Invalid port spect")
		}

		min, err = strconv.Atoi(portMinMax[0])
		if err != nil || min < 0 {
			return nil, errors.New("Min is not a valid port")
		}

		max, err = strconv.Atoi(portMinMax[1])
		if err != nil || max >= 65536 {
			return nil, errors.New("Max is not a valid port")
		}

		if min > max {
			return nil, errors.New("Min is greater than max")
		}
	} else {
		min, err = strconv.Atoi(ports)
		if err != nil || min >= 65536 || min < 0 {
			return nil, errors.New("Port is larger than 2^16 or invalid port")
		}
		max = min
	}

	return &PortSpec{
		Min:   uint16(min),
		Max:   uint16(max),
		value: value,
	}, nil
}

// IsMultiPort returns true if the spec is for multiple ports
func (s *PortSpec) IsMultiPort() bool {
	return s.Min != s.Max
}

// SinglePort returns the port of a non multi-port spec
func (s *PortSpec) SinglePort() (uint16, error) {
	if s.IsMultiPort() {
		return 0, errors.New("Not a single port specification")
	}

	return s.Min, nil
}

// MultiPort returns the multi-port range as a string
func (s *PortSpec) MultiPort() (string, error) {
	if s.IsMultiPort() {
		return strconv.Itoa(int(s.Min)) + ":" + strconv.Itoa(int(s.Max)), nil
	}

	return "", errors.New("Not a multiport specification")
}

// PortCache is a generic cache of port pairs or exact ports. It can store
// and do lookups of ports on exact matches or ranges. It returns the stored
// values
type PortCache struct {
	ports  cache.DataStore
	ranges []*PortSpec
}

// NewPortCache creates a new port cache
func NewPortCache(name string) *PortCache {
	return &PortCache{
		ports:  cache.NewCache(name),
		ranges: []*PortSpec{},
	}
}

// AddPortSpec adds a port spec into the cache
func (p *PortCache) AddPortSpec(s *PortSpec) {
	if s.Min == s.Max {
		p.ports.AddOrUpdate(s.Min, s)
	} else {
		p.ranges = append(p.ranges, s)
	}
}

// AddUnique adds a port spec into the cache
func (p *PortCache) AddUnique(s *PortSpec) error {
	if s.Min == s.Max {
		if err := p.ports.Add(s.Min, s); err != nil {
			return err
		}
	}
	for _, r := range p.ranges {
		if r.Max <= s.Min || r.Min >= s.Max {
			continue
		}
		return fmt.Errorf("Overlap detected: %d %d ", r.Max, r.Min)
	}
	p.ranges = append(p.ranges, s)
	return nil
}

// GetSpecFromPort searches the cache for a match based on a port
// It will return the first match found on exact ports or on the ranges
// of ports. If there are multiple intervals that match it will randomly
// return one of them.
func (p *PortCache) GetSpecFromPort(port uint16) (interface{}, error) {
	if spec, err := p.ports.Get(port); err == nil {
		return spec.(*PortSpec).value, nil
	}

	for _, s := range p.ranges {
		if s.Min <= port && port < s.Max {
			return s.value, nil
		}
	}

	return nil, fmt.Errorf("No match for port %d", port)
}

// GetAllSpecFromPort will return all the specs that potentially match. This
// will allow for overlapping ranges
func (p *PortCache) GetAllSpecFromPort(port uint16) ([]interface{}, error) {
	var allMatches []interface{}
	if spec, err := p.ports.Get(port); err == nil {
		allMatches = append(allMatches, spec.(*PortSpec).value)
	}

	for _, s := range p.ranges {
		if s.Min <= port && port < s.Max {
			allMatches = append(allMatches, s.value)
		}
	}

	if len(allMatches) == 0 {
		return nil, fmt.Errorf("No match for port %d", port)
	}
	return allMatches, nil
}

// Remove will remove a port from the cache
func (p *PortCache) Remove(s *PortSpec) error {

	if s.Min == s.Max {
		return p.ports.Remove(uint16(s.Min))
	}

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

	s, err := NewPortSpecFromString(ports, nil)
	if err != nil {
		return err
	}

	return p.Remove(s)
}
