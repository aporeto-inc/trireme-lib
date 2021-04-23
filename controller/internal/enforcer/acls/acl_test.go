package acls

import (
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
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
			Protocols: []string{constants.UDPProtoNum},
			Ports:     []string{"443"},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "udp0/0"}},
	}
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
			r, p, err := a.getMatchingAction(ip.To4(), port, packet.IPProtocolTCP, nil)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp172.17/16")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "tcp172.17/16")
		})

		Convey("When I lookup for a matching address with less specific match and a port range, I should get the right action", func() {
			ip := net.ParseIP("172.16.0.1")
			port := uint16(401)
			r, p, err := a.getMatchingAction(ip.To4(), port, packet.IPProtocolTCP, nil)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp172/8")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "tcp172/8")
		})

		Convey("When I lookup for a matching address exact port, I should get the right action", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(80)
			r, p, err := a.getMatchingAction(ip.To4(), port, packet.IPProtocolTCP, nil)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp192.168.100/24")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "tcp192.168.100/24")
		})

		Convey("When I lookup for a non matching address . I should get reject", func() {
			ip := net.ParseIP("192.168.200.1")
			port := uint16(80)
			r, p, err := a.getMatchingAction(ip.To4(), port, packet.IPProtocolTCP, nil)
			So(err, ShouldNotBeNil)
			So(p, ShouldBeNil)
			So(r, ShouldBeNil)
		})

		Convey("When I lookup for a matching address but failed port, I should get reject", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(600)
			r, p, err := a.getMatchingAction(ip.To4(), port, packet.IPProtocolTCP, nil)
			So(err, ShouldNotBeNil)
			So(p, ShouldBeNil)
			So(r, ShouldBeNil)
		})

		Convey("When I lookup for a matching exact address exact port, I should get the right action", func() {
			ip := net.ParseIP("10.1.1.1")
			port := uint16(80)
			r, p, err := a.getMatchingAction(ip.To4(), port, packet.IPProtocolTCP, nil)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp10.1.1.1")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "tcp10.1.1.1")
		})

	})
}

func TestICMPMatch(t *testing.T) {

	var icmpRules = policy.IPRuleList{
		policy.IPRule{
			Addresses: []string{"0.0.0.0/0"},
			Protocols: []string{"ICMP/8/1:3"},
			Ports:     []string{},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "icmp0/0-8/1:3",
			},
		},
		policy.IPRule{
			Addresses: []string{"684D:1111:222:3333:4444:5555:6:77"},
			Protocols: []string{"ICMP6"},
			Ports:     []string{},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "icmp6",
			},
		},
		policy.IPRule{
			Addresses: []string{"192.0.2.1"},
			Protocols: []string{"icmp"},
			Ports:     []string{},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "removeme",
			},
		},
	}

	Convey("Given a good DB", t, func() {

		a := newACL()
		So(a, ShouldNotBeNil)
		for _, r := range icmpRules {
			err := a.addRule(r)
			So(err, ShouldBeNil)
		}

		Convey("When I lookup for a matching address for icmp but wrong type or code, I should get the right action", func() {
			ip := net.ParseIP("172.17.0.1")
			r, p, err := a.matchICMPRule(ip.To4(), 8, 2)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "icmp0/0-8/1:3")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "icmp0/0-8/1:3")
		})

		Convey("When I lookup for a matching address for icmp, I should not get a match", func() {
			ip := net.ParseIP("172.17.0.1")
			r, p, err := a.matchICMPRule(ip.To4(), 8, 4)
			So(err, ShouldNotBeNil)
			So(p, ShouldBeNil)
			So(r, ShouldBeNil)
		})

		Convey("When I lookup for a matching address for icmp6, I should get the right action", func() {
			ip := net.ParseIP("684D:1111:222:3333:4444:5555:6:77")
			r, p, err := a.matchICMPRule(ip, 8, 1)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "icmp6")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "icmp6")
		})

		Convey("When I lookup for a non-matching address for icmp6, I should not get a match", func() {
			ip := net.ParseIP("684D:1111:222:3333:4444:5555:6:77")
			r, p, err := a.matchICMPRule(ip, 8, 1)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "icmp6")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "icmp6")
		})
	})
}

func TestICMPRemove(t *testing.T) {

	var icmpRules = policy.IPRuleList{
		policy.IPRule{
			Addresses: []string{"192.0.2.1"},
			Protocols: []string{"icmp"},
			Ports:     []string{},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "removeme",
			},
		},
	}

	removeMePolicy := &policy.FlowPolicy{
		Action:   policy.Accept,
		PolicyID: "removeme",
	}

	Convey("Given a good DB", t, func() {

		a := newACL()
		So(a, ShouldNotBeNil)
		for _, r := range icmpRules {
			err := a.addRule(r)
			So(err, ShouldBeNil)
		}

		Convey("When I try to remove a rule which does not exist, then it should not error", func() {
			ip := net.ParseIP("192.0.2.2")
			err := a.removeFromCache(ip, 32, false, "icmp", nil, removeMePolicy)
			So(err, ShouldBeNil)
		})

		Convey("When I try to remove a rule which does not match, then nothing should change", func() {
			ip := net.ParseIP("192.0.2.1")
			oldVal, ok := a.icmpCache.Get(ip, 32)
			So(ok, ShouldBeTrue)
			old := oldVal.([]*icmpRule)
			So(old, ShouldNotBeEmpty)
			err := a.removeFromCache(ip, 32, false, "icmp", nil, removeMePolicy)
			So(err, ShouldBeNil)
			newVal, ok := a.icmpCache.Get(ip, 32)
			So(ok, ShouldBeTrue)
			new := newVal.([]*icmpRule)
			So(new, ShouldNotBeEmpty)
			So(old, ShouldResemble, new)
		})

		Convey("When I try to remove a rule which matches, then it should get removed", func() {
			ip := net.ParseIP("192.0.2.1")
			oldVal, ok := a.icmpCache.Get(ip, 32)
			So(ok, ShouldBeTrue)
			old := oldVal.([]*icmpRule)
			So(old, ShouldNotBeEmpty)
			err := a.removeFromCache(ip, 32, false, "icmp", []string{}, removeMePolicy)
			So(err, ShouldBeNil)
			newVal, ok := a.icmpCache.Get(ip, 32)
			So(ok, ShouldBeTrue)
			new := newVal.([]*icmpRule)
			So(new, ShouldBeEmpty)
		})

	})
}

func TestRemove(t *testing.T) {

	// keep one policy here for a direct pointer comparison
	policyOne := &policy.FlowPolicy{
		Action:   policy.Accept,
		PolicyID: "1",
	}

	removeRules := policy.IPRuleList{
		policy.IPRule{
			Addresses: []string{"192.0.2.1"},
			Ports:     []string{"80"},
			Protocols: []string{constants.TCPProtoNum},
			Policy:    policyOne,
		},
		policy.IPRule{
			Addresses: []string{"192.0.2.1"},
			Ports:     []string{"80"},
			Protocols: []string{constants.UDPProtoNum},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "2",
			},
		},
	}

	// and one here for a content comparison
	policyTwo := &policy.FlowPolicy{
		Action:   policy.Accept,
		PolicyID: "2",
	}

	Convey("Given a good DB", t, func() {

		a := newACL()
		So(a, ShouldNotBeNil)
		for _, r := range removeRules {
			err := a.addRule(r)
			So(err, ShouldBeNil)
		}

		Convey("When I try to remove a rule with an unsupported protocol, then it should not error", func() {
			ip := net.ParseIP("192.0.2.1")
			err := a.removeFromCache(ip, 32, false, "unsupported", nil, nil)
			So(err, ShouldBeNil)
		})

		Convey("When I try to remove a TCP rule which does not exist, then it should not error", func() {
			ip := net.ParseIP("192.0.2.2")
			err := a.removeFromCache(ip, 32, false, constants.TCPProtoNum, []string{"42"}, nil)
			So(err, ShouldBeNil)
		})

		Convey("When I try to remove a TCP rule which cannot be parsed correctly, then it should error", func() {
			ip := net.ParseIP("192.0.2.1")
			err := a.removeFromCache(ip, 32, false, constants.TCPProtoNum, []string{"invalid port"}, nil)
			So(err, ShouldNotBeNil)
		})

		Convey("When I try to remove a UDP rule which does not exist, then it should not error", func() {
			ip := net.ParseIP("192.0.2.2")
			err := a.removeFromCache(ip, 32, false, constants.UDPProtoNum, []string{"43"}, nil)
			So(err, ShouldBeNil)
		})

		Convey("When I try to remove a UDP rule which cannot be parsed correctly, then it should error", func() {
			ip := net.ParseIP("192.0.2.1")
			err := a.removeFromCache(ip, 32, false, constants.UDPProtoNum, []string{"another invalid port"}, nil)
			So(err, ShouldNotBeNil)
		})

		Convey("When I try to remove a TCP rule which does not match, then nothing should change", func() {
			ip := net.ParseIP("192.0.2.1")
			oldVal, ok := a.tcpCache.Get(ip, 32)
			So(ok, ShouldBeTrue)
			old := oldVal.(portActionList)
			So(old, ShouldNotBeEmpty)
			err := a.removeFromCache(ip, 32, false, constants.TCPProtoNum, []string{"44"}, policyOne)
			So(err, ShouldBeNil)
			newVal, ok := a.tcpCache.Get(ip, 32)
			So(ok, ShouldBeTrue)
			new := newVal.(portActionList)
			So(new, ShouldNotBeEmpty)
			So(old, ShouldResemble, new)
		})

		Convey("When I try to remove a TCP rule which matches, then it should get removed", func() {
			ip := net.ParseIP("192.0.2.1")
			oldVal, ok := a.tcpCache.Get(ip, 32)
			So(ok, ShouldBeTrue)
			old := oldVal.(portActionList)
			So(old, ShouldNotBeEmpty)
			oldLength := len(old)
			err := a.removeFromCache(ip, 32, false, constants.TCPProtoNum, []string{"80"}, policyOne)
			So(err, ShouldBeNil)
			newVal, ok := a.tcpCache.Get(ip, 32)
			So(ok, ShouldBeTrue)
			new := newVal.(portActionList)
			So(new, ShouldHaveLength, oldLength-1)
		})

		Convey("When I try to remove a UDP rule which does not match, then nothing should change", func() {
			ip := net.ParseIP("192.0.2.1")
			oldVal, ok := a.udpCache.Get(ip, 32)
			So(ok, ShouldBeTrue)
			old := oldVal.(portActionList)
			So(old, ShouldNotBeEmpty)
			err := a.removeFromCache(ip, 32, false, constants.UDPProtoNum, []string{"45"}, policyTwo)
			So(err, ShouldBeNil)
			newVal, ok := a.udpCache.Get(ip, 32)
			So(ok, ShouldBeTrue)
			new := newVal.(portActionList)
			So(new, ShouldNotBeEmpty)
			So(old, ShouldResemble, new)
		})

		Convey("When I try to remove a UDP rule which matches, then it should get removed", func() {
			ip := net.ParseIP("192.0.2.1")
			oldVal, ok := a.udpCache.Get(ip, 32)
			So(ok, ShouldBeTrue)
			old := oldVal.(portActionList)
			So(old, ShouldNotBeEmpty)
			oldLength := len(old)
			err := a.removeFromCache(ip, 32, false, constants.UDPProtoNum, []string{"80"}, policyTwo)
			So(err, ShouldBeNil)
			newVal, ok := a.udpCache.Get(ip, 32)
			So(ok, ShouldBeTrue)
			new := newVal.(portActionList)
			So(new, ShouldHaveLength, oldLength-1)
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
			_, ok := a.tcpCache.Get(ip, size)
			So(ok, ShouldEqual, true)
		}

		Convey("When I lookup for a matching address and a port range, I should get the right action and observed action", func() {
			ip := net.ParseIP("200.17.0.1")
			port := uint16(401)
			r, p, err := a.getMatchingAction(ip.To4(), port, packet.IPProtocolTCP, nil)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp200/9")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "observed-continue-tcp200.17/17")
		})

		Convey("When I lookup for a matching address and a port range, I should get the observed action as applied", func() {
			ip := net.ParseIP("200.18.0.1")
			port := uint16(401)
			r, p, err := a.getMatchingAction(ip.To4(), port, packet.IPProtocolTCP, nil)
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
			r, p, err := a.getMatchingAction(ip.To4(), port, packet.IPProtocolTCP, preReported)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "observed-applied-tcp200.18/17")
			So(r.Action, ShouldEqual, policy.Reject)
			So(r.PolicyID, ShouldEqual, "preReportedPolicyID")
		})
	})
}

func TestNomatchLookup(t *testing.T) {

	ip1 := "200.17.0.0/16"
	ip2 := "200.18.0.0/16"
	ip3 := "200.0.0.0/8"
	var (
		rulesWithNomatch = policy.IPRuleList{
			policy.IPRule{
				Addresses: []string{"!" + ip1},
				Ports:     []string{"401"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "nomatch-tcp200.17/16"},
			},
			policy.IPRule{
				Addresses: []string{"!" + ip2},
				Ports:     []string{"401"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "nomatch-tcp200.18/16"},
			},
			policy.IPRule{
				Addresses: []string{ip3},
				Ports:     []string{"401"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "tcp200/8"},
			},
		}
	)

	Convey("Given a good DB", t, func() {
		a := newACL()
		So(a, ShouldNotBeNil)
		for _, r := range rulesWithNomatch {
			err := a.addRule(r)
			So(err, ShouldBeNil)
		}

		// Ensure all the elements are there in the cache
		cidrs := []string{ip1, ip2, ip3}

		for _, cidr := range cidrs {
			ip, ipnet, _ := net.ParseCIDR(cidr)
			size, _ := ipnet.Mask.Size()
			_, ok := a.tcpCache.Get(ip, size)
			So(ok, ShouldEqual, true)
		}

		Convey("When I lookup for a nomatch address and a port range, I should get nomatch", func() {
			ip := net.ParseIP("200.17.0.1")
			port := uint16(401)
			_, _, err := a.getMatchingAction(ip.To4(), port, packet.IPProtocolTCP, nil)
			So(err, ShouldNotBeNil)
		})

		Convey("When I lookup for another nomatch address and a port range, I should get nomatch", func() {
			ip := net.ParseIP("200.18.0.1")
			port := uint16(401)
			_, _, err := a.getMatchingAction(ip.To4(), port, packet.IPProtocolTCP, nil)
			So(err, ShouldNotBeNil)
		})

		Convey("When I lookup for a matching address and a port range, I should get the accept action", func() {
			ip := net.ParseIP("200.19.0.1")
			port := uint16(401)
			r, p, err := a.getMatchingAction(ip.To4(), port, packet.IPProtocolTCP, nil)
			So(err, ShouldBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp200/8")
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "tcp200/8")
		})
	})
}
