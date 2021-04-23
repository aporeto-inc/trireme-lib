package acls

import (
	"errors"
	"net"

	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

// ACLCache holds all the ACLS in an internal DB
// map[prefixes][subnets] -> list of ports with their actions
type ACLCache struct {
	reject  *acl
	accept  *acl
	observe *acl
}

// NewACLCache a new ACL cache
func NewACLCache() *ACLCache {
	return &ACLCache{
		reject:  newACL(),
		accept:  newACL(),
		observe: newACL(),
	}
}

// AddRule adds a single rule to the ACL Cache
func (c *ACLCache) AddRule(rule policy.IPRule) (err error) {

	if rule.Policy.ObserveAction.ObserveApply() {
		return c.observe.addRule(rule)
	}

	if rule.Policy.Action.Accepted() {
		return c.accept.addRule(rule)
	}

	return c.reject.addRule(rule)
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

// RemoveRulesForAddress is going to remove all rules for the provided address, protocol and ports.
func (c *ACLCache) RemoveRulesForAddress(address *Address, protocol string, ports []string, policy *policy.FlowPolicy) error {

	if err := c.reject.removeFromCache(address.IP, address.Mask, address.NoMatch, protocol, ports, policy); err != nil {
		return err
	}
	if err := c.accept.removeFromCache(address.IP, address.Mask, address.NoMatch, protocol, ports, policy); err != nil {
		return err
	}
	if err := c.observe.removeFromCache(address.IP, address.Mask, address.NoMatch, protocol, ports, policy); err != nil {
		return err
	}
	return nil
}

// RemoveIPMask removes the entries indexed with (ip, mask). This is an idempotent operation
// and thus does not returns an error
func (c *ACLCache) RemoveIPMask(ip net.IP, mask int) {

	c.reject.removeIPMask(ip, mask)
	c.accept.removeIPMask(ip, mask)
	c.observe.removeIPMask(ip, mask)
}

// GetMatchingAction gets the action from the acl cache
func (c *ACLCache) GetMatchingAction(ip net.IP, port uint16, proto uint8, defaultFlowPolicy *policy.FlowPolicy) (report *policy.FlowPolicy, packet *policy.FlowPolicy, err error) {

	report, packet, err = c.reject.getMatchingAction(ip, port, proto, report)
	if err == nil {
		return
	}

	report, packet, err = c.accept.getMatchingAction(ip, port, proto, report)
	if err == nil {
		return
	}

	report, packet, err = c.observe.getMatchingAction(ip, port, proto, report)
	if err == nil {
		return
	}

	if report == nil {
		report = defaultFlowPolicy
	}

	if packet == nil {
		packet = defaultFlowPolicy
	}

	if defaultFlowPolicy.Action.Accepted() {
		return report, packet, nil
	}

	return report, packet, errors.New("no match")
}

// GetMatchingICMPAction gets the action based on icmp policy
func (c *ACLCache) GetMatchingICMPAction(ip net.IP, icmpType, icmpCode int8, defaultFlowPolicy *policy.FlowPolicy) (report *policy.FlowPolicy, packet *policy.FlowPolicy, err error) {

	report, packet, err = c.reject.matchICMPRule(ip, icmpType, icmpCode)
	if err == nil {
		return
	}

	report, packet, err = c.accept.matchICMPRule(ip, icmpType, icmpCode)
	if err == nil {
		return
	}

	report, packet, err = c.observe.matchICMPRule(ip, icmpType, icmpCode)
	if err == nil {
		return
	}

	if report == nil {
		report = defaultFlowPolicy
	}

	if packet == nil {
		packet = defaultFlowPolicy
	}

	if defaultFlowPolicy.Action.Accepted() {
		return report, packet, nil
	}

	return report, packet, errors.New("no match")
}
