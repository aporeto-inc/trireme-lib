package acls

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/ipprefix"
)

// acl holds all the ACLS in an internal DB

type acl struct {
	cache ipprefix.IPcache
}

func newACL() *acl {
	return &acl{
		cache: ipprefix.NewIPCache(),
	}
}

// errNoMatchFromRule must stop the LPM check
var errNoMatchFromRule = errors.New("No Match")
var errNotFound = errors.New("No Match")

func (a *acl) addToCache(ip net.IP, mask int, port string, policy *policy.FlowPolicy, nomatch bool) error {
	var err error
	var portList portActionList

	r, err := newPortAction(port, policy, nomatch)
	if err != nil {
		return fmt.Errorf("unable to create port action: %s", err)
	}

	val, exists := a.cache.Get(ip, mask)
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

	a.cache.Put(ip, mask, portList)

	return nil
}

func (a *acl) removeIPMask(ip net.IP, mask int) {
	a.cache.Put(ip, mask, nil)
}

func (a *acl) matchRule(ip net.IP, port uint16, preReport *policy.FlowPolicy) (report *policy.FlowPolicy, packet *policy.FlowPolicy, err error) {
	report = preReport

	err = errNotFound

	lookup := func(val interface{}) bool {
		if val != nil {
			portList := val.(portActionList)

			report, packet, err = portList.lookup(port, report)
			if err == nil || err == errNoMatchFromRule {
				return true
			}
		}
		return false
	}

	a.cache.RunFuncOnLpmIP(ip, lookup)

	return report, packet, err
}

func (a *acl) addRule(rule policy.IPRule) (err error) {

	addCache := func(address, port string) error {
		var mask int
		parts := strings.Split(address, "/")
		ip := net.ParseIP(parts[0])
		nomatch := strings.HasPrefix(parts[0], "!")
		if nomatch {
			parts[0] = parts[0][1:]
		}
		if ip == nil {
			return fmt.Errorf("invalid ip address: %s", parts[0])
		}

		if len(parts) == 1 {
			if ip.To4() != nil {
				mask = 32
			} else {
				mask = 128
			}
		} else {
			mask, err = strconv.Atoi(parts[1])
			if err != nil {
				return fmt.Errorf("invalid address: %s", err)
			}
		}

		if err := a.addToCache(ip, mask, port, rule.Policy, nomatch); err != nil {
			return err
		}

		return nil
	}

	for _, proto := range rule.Protocols {
		if strings.ToLower(proto) != constants.TCPProtoNum {
			continue
		}
		for _, address := range rule.Addresses {
			for _, port := range rule.Ports {
				if err := addCache(address, port); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// getMatchingAction does lookup in acl in a common way for accept/reject rules.
func (a *acl) getMatchingAction(ip net.IP, port uint16, preReport *policy.FlowPolicy) (report *policy.FlowPolicy, packet *policy.FlowPolicy, err error) {

	return a.matchRule(ip, port, preReport)
}
