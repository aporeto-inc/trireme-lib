package acls

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"

	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/ipprefix"
	"go.aporeto.io/gaia/protocols"
)

// acl holds all the ACLS in an internal DB

type acl struct {
	tcpCache  ipprefix.IPcache
	udpCache  ipprefix.IPcache
	icmpCache ipprefix.IPcache
}

func newACL() *acl {
	return &acl{
		tcpCache:  ipprefix.NewIPCache(),
		udpCache:  ipprefix.NewIPCache(),
		icmpCache: ipprefix.NewIPCache(),
	}
}

// errNoMatchFromRule must stop the LPM check
var errNoMatchFromRule = errors.New("No Match")
var errNotFound = errors.New("No Match")

func (a *acl) addICMPToCache(ip net.IP, mask int, baseRule string, listOfDisjunctives []string, policy *policy.FlowPolicy) {
	var icmpRuleList []*icmpRule

	val, exists := a.icmpCache.Get(ip, mask)
	if !exists {
		icmpRuleList = []*icmpRule{}
	} else {
		icmpRuleList = val.([]*icmpRule)
	}

	newRule := &icmpRule{baseRule, listOfDisjunctives, policy}
	icmpRuleList = append(icmpRuleList, newRule)
	a.icmpCache.Put(ip, mask, icmpRuleList)
}

func (a *acl) removeICMPFromCache(ip net.IP, mask int, baseRule string, listOfDisjunctives []string, policy *policy.FlowPolicy) error {
	var icmpRuleList []*icmpRule
	val, exists := a.icmpCache.Get(ip, mask)
	if !exists {
		// nothing to remove
		return nil
	}
	icmpRuleList = val.([]*icmpRule)

	searchRule := icmpRule{baseRule, listOfDisjunctives, policy}
	newIcmpRuleList := make([]*icmpRule, 0, len(icmpRuleList))
	for _, rule := range icmpRuleList {
		if reflect.DeepEqual(searchRule, *rule) {
			// this is a full match, skip
			continue
		}
		// TODO: partial matches aren't handled. Should they?
		newIcmpRuleList = append(newIcmpRuleList, rule)
	}

	a.icmpCache.Put(ip, mask, newIcmpRuleList)

	return nil
}

func (a *acl) removeFromCache(ip net.IP, mask int, nomatch bool, proto string, ports []string, policy *policy.FlowPolicy) error {

	removeICMPCache := func(baseRule string, listOfDisjunctives []string) error {
		return a.removeICMPFromCache(ip, mask, baseRule, listOfDisjunctives, policy)
	}

	// the TCP or UDP cases use this part
	removeCache := func(lookupCache ipprefix.IPcache, port string) error {
		val, exists := lookupCache.Get(ip, mask)
		if !exists {
			// nothing to remove
			return nil
		}
		portList := val.(portActionList)

		newPortList := make(portActionList, 0, len(portList))
		r, err := newPortAction(port, policy, nomatch)
		if err != nil {
			return fmt.Errorf("unable to create port action: %s", err)
		}

		for _, portAction := range portList {
			if reflect.DeepEqual(*r, *portAction) {
				// this is a full match, skip
				continue
			}
			// TODO: partial matches aren't handled. Should they?
			newPortList = append(newPortList, portAction)
		}

		lookupCache.Put(ip, mask, newPortList)

		return nil
	}

	switch strings.ToLower(proto) {
	case constants.TCPProtoNum:
		for _, port := range ports {
			if err := removeCache(a.tcpCache, port); err != nil {
				return err
			}
		}
		return nil

	case constants.UDPProtoNum:
		for _, port := range ports {
			if err := removeCache(a.udpCache, port); err != nil {
				return err
			}
		}
		return nil

	default:
		// ICMP protocol
		if splits := strings.Split(proto, "/"); strings.ToUpper(splits[0]) == protocols.L4ProtocolICMP || strings.ToUpper(splits[0]) == protocols.L4ProtocolICMP6 {
			return removeICMPCache(proto, ports)
		}

		// unknown protocol - nothing to do
		return nil
	}
}

func (a *acl) addToCache(ip net.IP, mask int, port string, proto string, policy *policy.FlowPolicy, nomatch bool) error {
	var err error
	var portList portActionList
	var lookupCache ipprefix.IPcache
	switch strings.ToLower(proto) {
	case constants.TCPProtoNum:
		{
			lookupCache = a.tcpCache
		}
	case constants.UDPProtoNum:
		{
			lookupCache = a.udpCache
		}
	default:
		return nil
	}
	r, err := newPortAction(port, policy, nomatch)
	if err != nil {
		return fmt.Errorf("unable to create port action: %s", err)
	}
	val, exists := lookupCache.Get(ip, mask)
	if !exists {
		portList = portActionList{}
	} else {
		portList = val.(portActionList)
	}

	/* check if this is duplicate entry */
	for _, portAction := range portList {
		if *r == *portAction {
			return nil
		}
	}

	portList = append(portList, r)
	lookupCache.Put(ip, mask, portList)

	return nil
}

func (a *acl) removeIPMask(ip net.IP, mask int) {
	a.tcpCache.Put(ip, mask, nil)
	a.udpCache.Put(ip, mask, nil)
	a.icmpCache.Put(ip, mask, nil)
}

func (a *acl) matchRule(ip net.IP, port uint16, proto uint8, preReport *policy.FlowPolicy) (report *policy.FlowPolicy, packetPolicy *policy.FlowPolicy, err error) {
	report = preReport

	err = errNotFound

	lookup := func(val interface{}) bool {
		if val != nil {
			portList := val.(portActionList)

			report, packetPolicy, err = portList.lookup(port, report)
			if err == nil || err == errNoMatchFromRule {
				return true
			}
		}
		return false
	}
	if proto == packet.IPProtocolTCP {
		a.tcpCache.RunFuncOnLpmIP(ip, lookup)
	} else if proto == packet.IPProtocolUDP {
		a.udpCache.RunFuncOnLpmIP(ip, lookup)
	}

	return report, packetPolicy, err
}

func (a *acl) addRule(rule policy.IPRule) (err error) {

	addCache := func(address, port, proto string) error {
		addr, err := ParseAddress(address)
		if err != nil {
			return err
		}

		if err := a.addToCache(addr.IP, addr.Mask, port, proto, rule.Policy, addr.NoMatch); err != nil {
			return err
		}

		return nil
	}

	addICMPCache := func(address, baseRule string, listOfDisjunctives []string) error {
		addr, err := ParseAddress(address)
		if err != nil {
			return err
		}

		a.addICMPToCache(addr.IP, addr.Mask, baseRule, listOfDisjunctives, rule.Policy)

		return nil
	}

	for _, proto := range rule.Protocols {
		switch strings.ToLower(proto) {
		case constants.TCPProtoNum, constants.UDPProtoNum:
			for _, address := range rule.Addresses {
				for _, port := range rule.Ports {
					if err := addCache(address, port, proto); err != nil {
						return err
					}
				}
			}
		}
		if splits := strings.Split(proto, "/"); strings.ToUpper(splits[0]) == protocols.L4ProtocolICMP || strings.ToUpper(splits[0]) == protocols.L4ProtocolICMP6 {
			for _, address := range rule.Addresses {
				if err := addICMPCache(address, proto, rule.Ports); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// getMatchingAction does lookup in acl in a common way for accept/reject rules.
func (a *acl) getMatchingAction(ip net.IP, port uint16, proto uint8, preReport *policy.FlowPolicy) (report *policy.FlowPolicy, packet *policy.FlowPolicy, err error) {

	return a.matchRule(ip, port, proto, preReport)
}
