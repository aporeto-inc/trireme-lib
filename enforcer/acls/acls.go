package acls

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/aporeto-inc/trireme/policy"
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
	prefixMap map[uint32]map[uint32]PortActionList
}

// NewACLCache creates a new ACL cache
func NewACLCache() *ACLCache {
	return &ACLCache{
		prefixMap: make(map[uint32]map[uint32]PortActionList),
	}
}

// createPortAction parses a port spec and creates the action
func createPortAction(rule policy.IPRule) *PortAction {

	p := &PortAction{}
	if strings.Contains(rule.Port, ":") {
		parts := strings.Split(rule.Port, ":")
		if len(parts) != 2 {
			return nil
		}

		port, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil
		}
		p.min = uint16(port)

		port, err = strconv.Atoi(parts[1])
		if err != nil {
			return nil
		}
		p.max = uint16(port)

	} else {
		port, err := strconv.Atoi(rule.Port)
		if err != nil {
			return nil
		}

		p.min = uint16(port)

		p.max = p.min
	}

	if p.min > p.max {
		return nil
	}

	p.policy = rule.Policy

	return p
}

// AddRule adds a single rule to the ACL Cache
func (c *ACLCache) AddRule(rule policy.IPRule) (err error) {
	var subnet, mask uint32

	if strings.ToLower(rule.Protocol) != "tcp" {
		return nil
	}

	parts := strings.Split(rule.Address, "/")

	subnetSlice := net.ParseIP(parts[0])
	if subnetSlice == nil {
		return fmt.Errorf("Invalid address")
	}

	subnet = binary.BigEndian.Uint32(subnetSlice.To4())

	switch len(parts) {
	case 1:
		mask = 0xFFFFFFFF
	case 2:
		maskvalue, err := strconv.Atoi(parts[1])
		if err != nil || mask > 32 {
			return fmt.Errorf("Invalid address")
		}
		mask = binary.BigEndian.Uint32(net.CIDRMask(maskvalue, 32))
	default:
		return fmt.Errorf("Invalid address")
	}

	if _, ok := c.prefixMap[mask]; !ok {
		c.prefixMap[mask] = make(map[uint32]PortActionList)
	}

	a := createPortAction(rule)
	if a == nil {
		return fmt.Errorf("Invalid port")
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

	return
}

// GetMatchingAction gets the matching action
func (c *ACLCache) GetMatchingAction(ip []byte, port uint16) (*policy.FlowPolicy, error) {

	addr := binary.BigEndian.Uint32(ip)
	// Iterate over all the bitmasks we have
	for bitmask, pmap := range c.prefixMap {

		// Do a lookup as a hash to see if we have a match
		if actionList, ok := pmap[addr&bitmask]; ok {

			// Scan the ports - TODO: better algorithm needed here
			for _, p := range actionList {
				if port >= p.min && port <= p.max {
					return p.policy, nil
				}
			}
		}
	}

	return &policy.FlowPolicy{Action: policy.Reject, PolicyID: "default", ServiceID: "default"}, fmt.Errorf("No match")
}
