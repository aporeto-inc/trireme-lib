package portspec

// This package manages all port spec functions and validations and can
// be reused by all other packages.

import (
	"errors"
	"strconv"
	"strings"
)

// PortSpec is the specification of a port or port range
type PortSpec struct {
	Min   uint16 `json:"Min,omitempty"`
	Max   uint16 `json:"Max,omitempty"`
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
			return nil, errors.New("Invalid port specification")
		}

		min, err = strconv.Atoi(portMinMax[0])
		if err != nil || min < 0 {
			return nil, errors.New("Min is not a valid port")
		}

		max, err = strconv.Atoi(portMinMax[1])
		if err != nil || max >= 65536 {
			return nil, errors.New("Max is not a valid port")
		}
	} else {
		min, err = strconv.Atoi(ports)
		if err != nil || min >= 65536 || min < 0 {
			return nil, errors.New("Port is larger than 2^16 or invalid port")
		}
		max = min
	}

	return NewPortSpec(uint16(min), uint16(max), value)
}

// IsMultiPort returns true if the spec is for multiple ports.
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

// Range returns the range of a spec.
func (s *PortSpec) Range() (uint16, uint16) {
	return s.Min, s.Max
}

// MultiPort returns the multi-port range as a string.
func (s *PortSpec) String() string {
	if s.IsMultiPort() {
		return strconv.Itoa(int(s.Min)) + ":" + strconv.Itoa(int(s.Max))
	}

	return strconv.Itoa(int(s.Min))
}

// Value returns the value of the portspec if one is there
func (s *PortSpec) Value() interface{} {
	return s.value
}

// Overlaps returns true if the provided port spec overlaps with the given one.
func (s *PortSpec) Overlaps(p *PortSpec) bool {
	a := p
	b := s
	if a.Min > b.Min {
		a = s
		b = p
	}
	if a.Max >= b.Min {
		return true
	}
	return false
}

// Intersects returns true if the provided port spec intersect with the given one.
func (s *PortSpec) Intersects(p *PortSpec) bool {
	if p.Min == p.Max {
		return s.IsIncluded(int(p.Min))
	}
	return s.IsIncluded(int(p.Min)) && s.IsIncluded(int(p.Max))
}

// IsIncluded returns trues if a port is within the range of the portspec
func (s *PortSpec) IsIncluded(port int) bool {
	p := uint16(port)
	if s.Min <= p && p <= s.Max {
		return true
	}
	return false
}
