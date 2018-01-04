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

// Value returns the value of the portspec if one is there
func (s *PortSpec) Value() interface{} {
	return s.value
}
