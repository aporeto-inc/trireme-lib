package acls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/aporeto-inc/trireme-lib/policy"
)

// PortAction captures the minimum and maximum ports for an action
type PortAction struct {
	min    uint16
	max    uint16
	policy *policy.FlowPolicy
}

// PortActionList is a list of Port Actions
type PortActionList []*PortAction

// ACLCache holds all the ACLS in an internal DB
// map[prefixes][subnets] -> list of ports with their actions
type ACLCache struct {
	sortedPrefixLens []int
	prefixLenToMask  map[int]uint32
	prefixMap        map[uint32]map[uint32]PortActionList
}

// NewACLCache creates a new ACL cache
func NewACLCache() *ACLCache {
	return &ACLCache{
		sortedPrefixLens: make([]int, 0),
		prefixLenToMask:  make(map[int]uint32),
		prefixMap:        make(map[uint32]map[uint32]PortActionList),
	}
}

// createPortAction parses a port spec and creates the action
func createPortAction(rule policy.IPRule) (*PortAction, error) {

	p := &PortAction{}
	if strings.Contains(rule.Port, ":") {
		parts := strings.Split(rule.Port, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port: %s", rule.Port)
		}

		port, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, err
		}
		p.min = uint16(port)

		port, err = strconv.Atoi(parts[1])
		if err != nil {
			return nil, err
		}
		p.max = uint16(port)

	} else {
		port, err := strconv.Atoi(rule.Port)
		if err != nil {
			return nil, err
		}

		p.min = uint16(port)
		p.max = p.min
	}

	if p.min > p.max {
		return nil, errors.New("min port is greater than max port")
	}

	p.policy = rule.Policy

	return p, nil
}

// AddRule adds a single rule to the ACL Cache
func (c *ACLCache) AddRule(rule policy.IPRule) error {
	var subnet, mask uint32

	if strings.ToLower(rule.Protocol) != "tcp" {
		return nil
	}

	parts := strings.Split(rule.Address, "/")

	subnetSlice := net.ParseIP(parts[0])
	if subnetSlice == nil {
		return fmt.Errorf("invalid ip address: %s", parts[0])
	}

	subnet = binary.BigEndian.Uint32(subnetSlice.To4())

	switch len(parts) {
	case 1:
		mask = 0xFFFFFFFF
		c.prefixLenToMask[0] = mask
	case 2:
		maskvalue, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("invalid address: %s", err)
		}
		if mask > 32 {
			return fmt.Errorf("invalid mask value: %d", mask)
		}
		mask = binary.BigEndian.Uint32(net.CIDRMask(maskvalue, 32))
		c.prefixLenToMask[32-maskvalue] = mask
	default:
		return fmt.Errorf("invalid address: %s", rule.Address)
	}

	if _, ok := c.prefixMap[mask]; !ok {
		c.prefixMap[mask] = make(map[uint32]PortActionList)
	}

	a, err := createPortAction(rule)
	if err != nil {
		return fmt.Errorf("unable to create port action: %s", err)
	}

	subnet = subnet & mask

	c.prefixMap[mask][subnet] = append(c.prefixMap[mask][subnet], a)
	return nil
}

// AddRuleList adds a list of rules to the cache
func (c *ACLCache) AddRuleList(rules policy.IPRuleList) (err error) {

	for _, rule := range rules {
		if err = c.AddRule(rule); err != nil {
			return
		}
	}

	// Get sorted prefix lengths
	for k := range c.prefixLenToMask {
		c.sortedPrefixLens = append(c.sortedPrefixLens, k)
	}
	sort.Ints(c.sortedPrefixLens)
	return
}

// GetMatchingAction gets the matching action
func (c *ACLCache) GetMatchingAction(ip []byte, port uint16) (report *policy.FlowPolicy, packet *policy.FlowPolicy, err error) {

	addr := binary.BigEndian.Uint32(ip)

	// Iterate over all the bitmasks we have
	for _, len := range c.sortedPrefixLens {

		bitmask, ok := c.prefixLenToMask[len]
		if !ok {
			continue
		}

		pmap, ok := c.prefixMap[bitmask]
		if !ok {
			continue
		}

		// Do a lookup as a hash to see if we have a match
		if actionList, ok := pmap[addr&bitmask]; ok {

			// Scan the ports - TODO: better algorithm needed here
			for _, p := range actionList {
				if port >= p.min && port <= p.max {

					// Check observed policies.
					if report == nil {
						report = p.policy
						packet = report
						if p.policy.ObserveAction.ObserveContinue() {
							continue
						} else if p.policy.ObserveAction.ObserveApply() {
							return report, packet, nil
						}
					}

					packet = p.policy
					if report == nil {
						report = packet
					}
					return report, packet, nil
				}
			}
		}
	}

	if report == nil {
		report = &policy.FlowPolicy{Action: policy.Reject, PolicyID: "default", ServiceID: "default"}
		packet = report
	}
	return report, packet, errors.New("no match")
}
