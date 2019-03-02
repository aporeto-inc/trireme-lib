package acls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/policy"
)

func newACL() *acl {
	return &acl{
		acl4: v4{sortedPrefixLens: []int{},
			prefixLenMap: map[int]*prefixRules4{},
		},
		acl6: v6{sortedPrefixLens: []int{},
			prefixLenMap: map[int]*prefixRules6{},
		},
	}
}

// acl holds all the ACLS in an internal DB
type v4 struct {
	sortedPrefixLens []int
	prefixLenMap     map[int]*prefixRules4
}

type v6 struct {
	sortedPrefixLens []int
	prefixLenMap     map[int]*prefixRules6
}

type acl struct {
	acl4 v4
	acl6 v6
}

func (a *v4) ipv4ruleAdd(address, port string, policy *policy.FlowPolicy) error {
	var subnet, mask uint32
	var err error

	parts := strings.Split(address, "/")

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
		return fmt.Errorf("invalid address: %s", address)
	}
	plenRules, ok := a.prefixLenMap[maskValue]
	if !ok {
		plenRules = &prefixRules4{
			mask:  mask,
			rules: make(map[uint32]portActionList),
		}
		a.prefixLenMap[maskValue] = plenRules
	}

	r, err := newPortAction(port, policy)
	if err != nil {
		return fmt.Errorf("unable to create port action: %s", err)
	}

	subnet = subnet & mask
	plenRules.rules[subnet] = append(plenRules.rules[subnet], r)
	a.sortedPrefixLens = append(a.sortedPrefixLens, maskValue)
	return nil
}

func maskSubnet(subnet, mask []byte) {
	for index, m := range subnet {
		subnet[index] = m & mask[index]
	}
}

func (a *v6) ipv6ruleAdd(address, port string, policy *policy.FlowPolicy) error {
	var maskValue int
	var mask [16]byte
	var err error

	parts := strings.Split(address, "/")
	subnet := net.ParseIP(parts[0]).To16()

	if len(subnet) != net.IPv6len {
		return fmt.Errorf("invalid ip address: %s", parts[0])
	}

	switch len(parts) {
	case 1:
		maskValue = 128

	case 2:
		maskValue, err = strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("invalid address: %s", err)
		}

	default:
		return fmt.Errorf("invalid address: %s", address)
	}

	createMask := func(maskValue int, mask []byte) {
		index := 0

		for maskValue >= 8 {
			mask[index] = 0xff
			index++
			maskValue -= 8
		}

		mask[index] = math.MaxUint8 << uint(8-maskValue)
	}

	createMask(maskValue, mask[:])

	plenRules, ok := a.prefixLenMap[maskValue]
	if !ok {
		plenRules = &prefixRules6{
			mask:  mask[:],
			rules: map[[16]byte]portActionList{},
		}
		a.prefixLenMap[maskValue] = plenRules
	}

	r, err := newPortAction(port, policy)
	if err != nil {
		return fmt.Errorf("unable to create port action: %s", err)
	}

	maskSubnet(subnet, mask[:])
	var subnetCopy [16]byte
	copy(subnetCopy[:], subnet)
	plenRules.rules[subnetCopy] = append(plenRules.rules[subnetCopy], r)
	a.sortedPrefixLens = append(a.sortedPrefixLens, maskValue)

	return nil
}

func (a *acl) addRule(rule policy.IPRule) (err error) {

	for _, proto := range rule.Protocols {
		if strings.ToLower(proto) == constants.TCPProtoNum {
			for _, address := range rule.Addresses {
				for _, port := range rule.Ports {

					parts := strings.Split(address, "/")
					ip := net.ParseIP(parts[0])
					if ip == nil {
						return fmt.Errorf("invalid ip address: %s", parts[0])
					}

					if ip.To4() != nil {
						if err := a.acl4.ipv4ruleAdd(address, port, rule.Policy); err != nil {
							return err
						}
					} else {
						if err := a.acl6.ipv6ruleAdd(address, port, rule.Policy); err != nil {
							return err
						}
					}

				}
			}
		}
	}

	return nil
}

func (a *v4) matchIpv4(ip []byte, port uint16, preReport *policy.FlowPolicy) (report *policy.FlowPolicy, packet *policy.FlowPolicy, err error) {
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

func (a *v6) matchIpv6(ip []byte, port uint16, preReport *policy.FlowPolicy) (report *policy.FlowPolicy, packet *policy.FlowPolicy, err error) {
	report = preReport

	// Iterate over all the bitmasks we have
	for _, len := range a.sortedPrefixLens {
		rules, ok := a.prefixLenMap[len]
		if !ok {
			continue
		}

		maskSubnet(ip, rules.mask)
		// Do a lookup as a hash to see if we have a match
		var ipCopy [16]byte
		copy(ipCopy[:], ip)
		actionList, ok := rules.rules[ipCopy]
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

// getMatchingAction does lookup in acl in a common way for accept/reject rules.
func (a *acl) getMatchingAction(ip []byte, port uint16, preReport *policy.FlowPolicy) (report *policy.FlowPolicy, packet *policy.FlowPolicy, err error) {

	if len(ip) == net.IPv4len {
		return a.acl4.matchIpv4(ip, port, preReport)
	}

	return a.acl6.matchIpv6(ip, port, preReport)
}
