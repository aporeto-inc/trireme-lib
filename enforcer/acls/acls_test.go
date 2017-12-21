package acls

import (
	"net"
	"testing"

	"github.com/aporeto-inc/trireme-lib/policy"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	rules = policy.IPRuleList{
		policy.IPRule{
			Address:  "172.0.0.0/8",
			Port:     "400:500",
			Protocol: "tcp",
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "tcp172/8"},
		},
		policy.IPRule{
			Address:  "172.17.0.0/16",
			Port:     "400:500",
			Protocol: "tcp",
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "tcp172.17/16"},
		},
		policy.IPRule{
			Address:  "192.168.100.0/24",
			Protocol: "tcp",
			Port:     "80",
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "tcp192.168.100/24"},
		},
		policy.IPRule{
			Address:  "10.1.1.1",
			Protocol: "tcp",
			Port:     "80",
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "tcp10.1.1.1"}},
		policy.IPRule{
			Address:  "0.0.0.0/0",
			Protocol: "tcp",
			Port:     "443",
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "tcp0/0"}},
		policy.IPRule{
			Address:  "0.0.0.0/0",
			Protocol: "udp",
			Port:     "443",
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "udp0/0"}},
	}
	// rulesPrefixLens holds unique prefix lens in rules above.
	rulesPrefixLens = 5

	rulesWithObservation = policy.IPRuleList{
		policy.IPRule{
			Address:  "200.0.0.0/9",
			Port:     "401",
			Protocol: "tcp",
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "tcp200/9"},
		},
		policy.IPRule{
			Address:  "200.17.0.0/17",
			Port:     "401",
			Protocol: "tcp",
			Policy: &policy.FlowPolicy{
				Action:        policy.Accept,
				ObserveAction: policy.ObserveContinue,
				PolicyID:      "observed-tcp200.17/17"},
		},
		policy.IPRule{
			Address:  "200.18.0.0/17",
			Port:     "401",
			Protocol: "tcp",
			Policy: &policy.FlowPolicy{
				Action:        policy.Accept,
				ObserveAction: policy.ObserveApply,
				PolicyID:      "observed-tcp200.18/17"},
		},
	}
	// rulesWithObservationPrefixLens holds unique prefix lens in rules above.
	rulesWithObservationPrefixLens = 2
)

func TestLookup(t *testing.T) {

	Convey("Given a good DB", t, func() {
		c := NewACLCache()
		err := c.AddRuleList(rules)
		So(err, ShouldBeNil)
		So(len(c.prefixMap), ShouldEqual, rulesPrefixLens)

		Convey("When I lookup for a matching address and a port range, I should get the right action", func() {
			ip := net.ParseIP("172.17.0.1")
			port := uint16(401)
			r, a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Accept)
			So(a.PolicyID, ShouldEqual, "tcp172.17/16")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "tcp172.17/16")
		})

		Convey("When I lookup for a matching address with less specific match and a port range, I should get the right action", func() {
			ip := net.ParseIP("172.16.0.1")
			port := uint16(401)
			r, a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Accept)
			So(a.PolicyID, ShouldEqual, "tcp172/8")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "tcp172/8")
		})

		Convey("When I lookup for a matching address exact port, I should get the right action", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(80)
			r, a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Accept)
			So(a.PolicyID, ShouldEqual, "tcp192.168.100/24")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "tcp192.168.100/24")
		})

		Convey("When I lookup for a non matching address . I should get reject", func() {
			ip := net.ParseIP("192.168.200.1")
			port := uint16(80)
			r, a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldNotBeNil)
			So(a.Action, ShouldEqual, policy.Reject)
			So(a.PolicyID, ShouldEqual, "default")
			So(r.Action, ShouldEqual, policy.Reject)
			So(r.PolicyID, ShouldEqual, "default")
		})

		Convey("When I lookup for a matching address but failed port, I should get reject", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(600)
			r, a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldNotBeNil)
			So(a.Action, ShouldEqual, policy.Reject)
			So(a.PolicyID, ShouldEqual, "default")
			So(r.Action, ShouldEqual, policy.Reject)
			So(r.PolicyID, ShouldEqual, "default")
		})

		Convey("When I lookup for a matching exact address exact port, I should get the right action", func() {
			ip := net.ParseIP("10.1.1.1")
			port := uint16(80)
			r, a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Accept)
			So(a.PolicyID, ShouldEqual, "tcp10.1.1.1")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "tcp10.1.1.1")
		})
	})
}

func TestObservedLookup(t *testing.T) {

	Convey("Given a good DB", t, func() {
		c := NewACLCache()
		err := c.AddRuleList(rulesWithObservation)
		So(err, ShouldBeNil)
		So(len(c.prefixMap), ShouldEqual, rulesWithObservationPrefixLens)

		Convey("When I lookup for a matching address and a port range, I should get the right action and observed action", func() {
			ip := net.ParseIP("200.17.0.1")
			port := uint16(401)
			r, a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Accept)
			So(a.PolicyID, ShouldEqual, "tcp200/9")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "observed-tcp200.17/17")
		})

		Convey("When I lookup for a matching address and a port range, I should get the observed action as applied", func() {
			ip := net.ParseIP("200.18.0.1")
			port := uint16(401)
			r, a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Accept)
			So(a.PolicyID, ShouldEqual, "observed-tcp200.18/17")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "observed-tcp200.18/17")
		})
	})
}
