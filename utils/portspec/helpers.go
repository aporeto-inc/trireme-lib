package portspec

import (
	"sort"
)

const lastValidPort = 65535

// GetUncoveredPortRanges returns non overlapping port ranges
func GetUncoveredPortRanges(portSpecs ...*PortSpec) ([]*PortSpec, error) {

	// If there are no portspecs return all the range
	if portSpecs == nil || len(portSpecs) <= 0 {
		p, err := NewPortSpec(1, lastValidPort, nil)
		if err != nil {
			return nil, err
		}
		return []*PortSpec{p}, nil
	}

	// Return the default port range if it covers all
	if portSpecs[0].Min == 1 && portSpecs[0].Max == lastValidPort {
		return []*PortSpec{portSpecs[0]}, nil
	}

	// Sort the slice by portspec min value
	sort.Slice(portSpecs, func(i, j int) bool {
		return portSpecs[i].Min < portSpecs[j].Min
	})

	var result []*PortSpec
	var currEnd uint16

	for _, portSpec := range portSpecs {
		// Check if current portSpec.Min is grater than portSpec.Max plus 1 , Incase they are consecutive
		if portSpec.Min > currEnd+1 {
			temp, err := NewPortSpec(currEnd+1, portSpec.Min-1, nil)
			if err != nil {
				return nil, err
			}
			result = append(result, temp)
		}
		// Change the currEnd to current portSpec.Max
		currEnd = portSpec.Max
	}

	// If there are no more portspec and is not the lastValidPort, then append the range to the list
	if currEnd != lastValidPort {
		temp, err := NewPortSpec(currEnd+1, lastValidPort, nil)
		if err != nil {
			return nil, err
		}
		result = append(result, temp)
	}

	return result, nil
}
