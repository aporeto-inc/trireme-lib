package acls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"go.aporeto.io/trireme-lib/policy"
)

func newACL() *acl {
	return &acl{
		sortedPrefixLens: make([]int, 0),
		prefixLenMap:     make(map[int]*prefixRules),
	}
}

// acl holds all the ACLS in an internal DB
type acl struct {
	sortedPrefixLens []int
	prefixLenMap     map[int]*prefixRules
}

func (a *acl) reverseSort() {

	// Get reverse sorted prefix lengths for reject rules
	for k := range a.prefixLenMap {
		a.sortedPrefixLens = append(a.sortedPrefixLens, k)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(a.sortedPrefixLens)))
}

func (a *acl) addRule(rule policy.IPRule) (err error) {

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

	maskValue := 0

	switch len(parts) {
	case 1:
		mask = 0xFFFFFFFF
		maskValue = 32

	case 2:
		maskValue, err = strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("invalid address: %s", err)
		}

		if mask > 32 {
			return fmt.Errorf("invalid mask value: %d", mask)
		}
		mask = binary.BigEndian.Uint32(net.CIDRMask(maskValue, 32))

	default:
		return fmt.Errorf("invalid address: %s", rule.Address)
	}
	plenRules, ok := a.prefixLenMap[maskValue]
	if !ok {
		plenRules = &prefixRules{
			mask:  mask,
			rules: make(map[uint32]portActionList),
		}
		a.prefixLenMap[maskValue] = plenRules
	}

	r, err := newPortAction(rule)
	if err != nil {
		return fmt.Errorf("unable to create port action: %s", err)
	}

	subnet = subnet & mask
	plenRules.rules[subnet] = append(plenRules.rules[subnet], r)
	return nil
}

// getMatchingAction does lookup in acl in a common way for accept/reject rules.
func (a *acl) getMatchingAction(ip []byte, port uint16, preReport *policy.FlowPolicy) (report *policy.FlowPolicy, packet *policy.FlowPolicy, err error) {

	report = preReport

	addr := binary.BigEndian.Uint32(ip)

	// Iterate over all the bitmasks we have
	for _, len := range a.sortedPrefixLens {

		rules, ok := a.prefixLenMap[len]
		if !ok {
			continue
		}

		// Do a lookup as a hash to see if we have a match
		actionList, ok := rules.rules[addr&rules.mask]
		if !ok {
			continue
		}

		report, packet, err = actionList.lookup(port, report)
		if err == nil {
			return
		}
	}

	return report, packet, errors.New("No match")
}
