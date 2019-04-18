package acls

import (
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/policy"
)

var (
	rules = policy.IPRuleList{
		policy.IPRule{
			Addresses: []string{"172.0.0.0/8"},
			Ports:     []string{"400:500"},
			Protocols: []string{constants.TCPProtoNum},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "tcp172/8"},
		},
		policy.IPRule{
			Addresses: []string{"172.17.0.0/16"},
			Ports:     []string{"400:500"},
			Protocols: []string{constants.TCPProtoNum},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "tcp172.17/16"},
		},
		policy.IPRule{
			Addresses: []string{"192.168.100.0/24"},
			Protocols: []string{constants.TCPProtoNum},
			Ports:     []string{"80"},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "tcp192.168.100/24"},
		},
		policy.IPRule{
			Addresses: []string{"10.1.1.1"},
			Protocols: []string{constants.TCPProtoNum},
			Ports:     []string{"80"},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "tcp10.1.1.1"}},
		policy.IPRule{
			Addresses: []string{"0.0.0.0/0"},
			Protocols: []string{constants.TCPProtoNum},
			Ports:     []string{"443"},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "tcp0/0"}},
		policy.IPRule{
			Addresses: []string{"0.0.0.0/0"},
			Protocols: []string{"udp"},
			Ports:     []string{"443"},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "udp0/0"}},
	}
	// rulesPrefixLens holds unique prefix lens in rules above.
//	rulesPrefixLens = 5
)

func TestLookup(t *testing.T) {

	Convey("Given a good DB", t, func() {

		a := newACL()
		So(a, ShouldNotBeNil)
		for _, r := range rules {
			err := a.addRule(r)
			So(err, ShouldBeNil)
		}

		Convey("When I lookup for a matching address and a port range, I should get the right action", func() {
			ip := net.ParseIP("172.17.0.1")
			port := uint16(401)
			r, p, err := a.getMatchingAction(ip.To4(), port, nil)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp172.17/16")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "tcp172.17/16")
		})

		Convey("When I lookup for a matching address with less specific match and a port range, I should get the right action", func() {
			ip := net.ParseIP("172.16.0.1")
			port := uint16(401)
			r, p, err := a.getMatchingAction(ip.To4(), port, nil)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp172/8")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "tcp172/8")
		})

		Convey("When I lookup for a matching address exact port, I should get the right action", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(80)
			r, p, err := a.getMatchingAction(ip.To4(), port, nil)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp192.168.100/24")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "tcp192.168.100/24")
		})

		Convey("When I lookup for a non matching address . I should get reject", func() {
			ip := net.ParseIP("192.168.200.1")
			port := uint16(80)
			r, p, err := a.getMatchingAction(ip.To4(), port, nil)
			So(err, ShouldNotBeNil)
			So(p, ShouldBeNil)
			So(r, ShouldBeNil)
		})

		Convey("When I lookup for a matching address but failed port, I should get reject", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(600)
			r, p, err := a.getMatchingAction(ip.To4(), port, nil)
			So(err, ShouldNotBeNil)
			So(p, ShouldBeNil)
			So(r, ShouldBeNil)
		})

		Convey("When I lookup for a matching exact address exact port, I should get the right action", func() {
			ip := net.ParseIP("10.1.1.1")
			port := uint16(80)
			r, p, err := a.getMatchingAction(ip.To4(), port, nil)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp10.1.1.1")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "tcp10.1.1.1")
		})
	})
}

func TestObservedLookup(t *testing.T) {

	ip1 := "200.17.0.0/17"
	ip2 := "200.18.0.0/17"
	ip3 := "200.0.0.0/9"
	var (
		rulesWithObservation = policy.IPRuleList{
			policy.IPRule{
				Addresses: []string{ip1},
				Ports:     []string{"401"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					Action:        policy.Accept,
					ObserveAction: policy.ObserveContinue,
					PolicyID:      "observed-continue-tcp200.17/17"},
			},
			policy.IPRule{
				Addresses: []string{ip2},
				Ports:     []string{"401"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					Action:        policy.Accept,
					ObserveAction: policy.ObserveApply,
					PolicyID:      "observed-applied-tcp200.18/17"},
			},
			policy.IPRule{
				Addresses: []string{ip3},
				Ports:     []string{"401"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "tcp200/9"},
			},
		}
	)

	Convey("Given a good DB", t, func() {
		a := newACL()
		So(a, ShouldNotBeNil)
		for _, r := range rulesWithObservation {
			err := a.addRule(r)
			So(err, ShouldBeNil)
		}

		// Ensure all the elements are there in the cache
		cidrs := []string{ip1, ip2, ip3}

		for _, cidr := range cidrs {
			ip, ipnet, _ := net.ParseCIDR(cidr)
			size, _ := ipnet.Mask.Size()
			_, ok := a.cache.Get(ip, size)
			So(ok, ShouldEqual, true)
		}

		Convey("When I lookup for a matching address and a port range, I should get the right action and observed action", func() {
			ip := net.ParseIP("200.17.0.1")
			port := uint16(401)
			r, p, err := a.getMatchingAction(ip.To4(), port, nil)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp200/9")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "observed-continue-tcp200.17/17")
		})

		Convey("When I lookup for a matching address and a port range, I should get the observed action as applied", func() {
			ip := net.ParseIP("200.18.0.1")
			port := uint16(401)
			r, p, err := a.getMatchingAction(ip.To4(), port, nil)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "observed-applied-tcp200.18/17")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "observed-applied-tcp200.18/17")
		})

		Convey("When I lookup for a matching address and a port range with an already reported action of reject, I should get the observed action as applied", func() {
			ip := net.ParseIP("200.18.0.1")
			port := uint16(401)
			preReported := &policy.FlowPolicy{
				Action:   policy.Reject,
				PolicyID: "preReportedPolicyID",
			}
			r, p, err := a.getMatchingAction(ip.To4(), port, preReported)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "observed-applied-tcp200.18/17")
			So(r.Action, ShouldEqual, policy.Reject)
			So(r.PolicyID, ShouldEqual, "preReportedPolicyID")
		})
	})
}
