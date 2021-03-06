// +build !windows

package acls

import (
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

var catchAllPolicy = &policy.FlowPolicy{Action: policy.Reject | policy.Log, PolicyID: "default", ServiceID: "default"}

func TestEmptyACLCacheLookup(t *testing.T) {

	Convey("Given an empty ACL Cache", t, func() {
		c := NewACLCache()
		Convey("When I lookup for a matching address but failed port, I should get reject", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(600)
			a, p, err := c.GetMatchingAction(ip.To4(), port, packet.IPProtocolTCP, catchAllPolicy)
			So(err, ShouldNotBeNil)
			So(a.Action&policy.Reject, ShouldEqual, policy.Reject)
			So(a.PolicyID, ShouldEqual, "default")
			So(p.Action&policy.Reject, ShouldEqual, policy.Reject)
			So(p.ServiceID, ShouldEqual, "default")
		})

		Convey("When I lookup for a matching address but failed port, I should get accept", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(600)
			defaultFlowPolcy := &policy.FlowPolicy{Action: policy.Accept | policy.Log, PolicyID: "default", ServiceID: "default"}
			a, p, err := c.GetMatchingAction(ip.To4(), port, packet.IPProtocolTCP, defaultFlowPolcy)
			So(err, ShouldBeNil)
			So(a.Action&policy.Accept, ShouldEqual, policy.Accept)
			So(a.PolicyID, ShouldEqual, "default")
			So(p.Action&policy.Accept, ShouldEqual, policy.Accept)
			So(p.ServiceID, ShouldEqual, "default")
		})
	})
}

func TestRejectPrioritizedOverAcceptCacheLookup(t *testing.T) {

	rules = policy.IPRuleList{
		policy.IPRule{
			Addresses: []string{"172.0.0.0/8"},
			Ports:     []string{"1"},
			Protocols: []string{constants.TCPProtoNum},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "tcp172/8"},
		},
		policy.IPRule{
			Addresses: []string{"0.0.0.0/0"},
			Ports:     []string{"1"},
			Protocols: []string{constants.TCPProtoNum},
			Policy: &policy.FlowPolicy{
				Action:   policy.Reject,
				PolicyID: "catchAllDrop"},
		},
	}

	Convey("Given an ACL Cache with accept and reject rules", t, func() {
		c := NewACLCache()
		So(c, ShouldNotBeNil)
		err := c.AddRuleList(rules)
		So(err, ShouldBeNil)

		Convey("When I lookup for a matching address to both accept and reject rule, I should get reject", func() {
			ip := net.ParseIP("172.1.1.1")
			port := uint16(1)
			a, p, err := c.GetMatchingAction(ip.To4(), port, packet.IPProtocolTCP, catchAllPolicy)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Reject)
			So(a.PolicyID, ShouldEqual, "catchAllDrop")
			So(p.Action, ShouldEqual, policy.Reject)
			So(p.PolicyID, ShouldEqual, "catchAllDrop")
		})
	})
}

func TestEmptyACLWithObserveContinueCacheLookup(t *testing.T) {

	rules = policy.IPRuleList{
		policy.IPRule{
			Addresses: []string{"0.0.0.0/0"},
			Ports:     []string{"1"},
			Protocols: []string{constants.TCPProtoNum},
			Policy: &policy.FlowPolicy{
				Action:        policy.Accept,
				ObserveAction: policy.ObserveContinue,
				PolicyID:      "ObserveAcceptContinue"},
		},
	}

	Convey("Given an empty ACL Cache", t, func() {
		c := NewACLCache()
		So(c, ShouldNotBeNil)
		err := c.AddRuleList(rules)
		So(err, ShouldBeNil)

		Convey("When I lookup for a matching address, I should get accept", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(1)
			a, p, err := c.GetMatchingAction(ip.To4(), port, packet.IPProtocolTCP, catchAllPolicy)
			So(err, ShouldNotBeNil)
			So(a.Action, ShouldEqual, policy.Accept)
			So(a.PolicyID, ShouldEqual, "ObserveAcceptContinue")
			So(p.Action&policy.Reject, ShouldEqual, policy.Reject)
			So(p.PolicyID, ShouldEqual, "default")
		})
	})
}

func TestEmptyACLWithObserveApplyCacheLookup(t *testing.T) {

	rules = policy.IPRuleList{
		policy.IPRule{
			Addresses: []string{"0.0.0.0/0"},
			Ports:     []string{"1"},
			Protocols: []string{constants.TCPProtoNum},
			Policy: &policy.FlowPolicy{
				Action:        policy.Accept,
				ObserveAction: policy.ObserveApply,
				PolicyID:      "observeAcceptApply"},
		},
	}

	Convey("Given an empty ACL Cache", t, func() {
		c := NewACLCache()
		So(c, ShouldNotBeNil)
		err := c.AddRuleList(rules)
		So(err, ShouldBeNil)

		Convey("When I lookup for a matching address, I should get accept", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(1)
			a, p, err := c.GetMatchingAction(ip.To4(), port, packet.IPProtocolTCP, catchAllPolicy)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Accept)
			So(a.PolicyID, ShouldEqual, "observeAcceptApply")
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "observeAcceptApply")
		})
	})
}

func TestObserveContinueApplyCacheLookup(t *testing.T) {

	rules = policy.IPRuleList{
		policy.IPRule{
			Addresses: []string{"172.1.0.0/16"},
			Ports:     []string{"1"},
			Protocols: []string{constants.TCPProtoNum},
			Policy: &policy.FlowPolicy{
				Action:        policy.Reject,
				ObserveAction: policy.ObserveContinue,
				PolicyID:      "observeRejectContinue-172.1/16"},
		},
		policy.IPRule{
			Addresses: []string{"172.0.0.0/8"},
			Ports:     []string{"1"},
			Protocols: []string{constants.TCPProtoNum},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "tcp172/8"},
		},
		policy.IPRule{
			Addresses: []string{"172.0.0.0/8"},
			Ports:     []string{"1"},
			Protocols: []string{constants.TCPProtoNum},
			Policy: &policy.FlowPolicy{
				Action:        policy.Accept,
				ObserveAction: policy.ObserveApply,
				PolicyID:      "observeRejectApply"},
		},
		policy.IPRule{
			Addresses: []string{"172.0.0.0/8"},
			Ports:     []string{"1"},
			Protocols: []string{constants.TCPProtoNum},
			Policy: &policy.FlowPolicy{
				Action:        policy.Reject,
				ObserveAction: policy.ObserveContinue,
				PolicyID:      "observeRejectContinue"},
		},
	}

	Convey("Given an ACL Cache with accept observe-apply and observe-continue rules for same prefix", t, func() {
		c := NewACLCache()
		So(c, ShouldNotBeNil)
		err := c.AddRuleList(rules)
		So(err, ShouldBeNil)

		Convey("When I lookup for a matching address to /16, I should get report reject and packet accept and ignore observe-apply rule", func() {
			ip := net.ParseIP("172.1.1.1")
			port := uint16(1)
			a, p, err := c.GetMatchingAction(ip.To4(), port, packet.IPProtocolTCP, catchAllPolicy)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Reject)
			So(a.PolicyID, ShouldEqual, "observeRejectContinue-172.1/16")
			// So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp172/8")
		})

		Convey("When I lookup for a matching address to /8, I should get report reject and packet accept and ignore observe-apply rule", func() {
			ip := net.ParseIP("172.2.1.1")
			port := uint16(1)
			a, p, err := c.GetMatchingAction(ip.To4(), port, packet.IPProtocolTCP, catchAllPolicy)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Reject)
			So(a.PolicyID, ShouldEqual, "observeRejectContinue")
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp172/8")
		})
	})
}

func TestAcceptWithNomatchCacheLookup(t *testing.T) {

	rules = policy.IPRuleList{
		policy.IPRule{
			Addresses: []string{"0.0.0.0/1", "!10.10.10.0/24", "128.0.0.0/1", "!10.0.0.0/8", "10.10.0.0/16"},
			Ports:     []string{"0:65535"},
			Protocols: []string{constants.TCPProtoNum},
			Policy: &policy.FlowPolicy{
				Action: policy.Accept,
			},
		},
	}

	Convey("Given an ACL Cache with accept policy with some nomatch addresses", t, func() {
		c := NewACLCache()
		So(c, ShouldNotBeNil)
		err := c.AddRuleList(rules)
		So(err, ShouldBeNil)

		Convey("When I lookup address within nomatch outer but also within match inner, I should get accept", func() {
			ip := net.ParseIP("10.10.2.100")
			port := uint16(443)
			a, p, err := c.GetMatchingAction(ip.To4(), port, packet.IPProtocolTCP, catchAllPolicy)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Accept)
			So(p.Action, ShouldEqual, policy.Accept)
		})

		Convey("When I lookup address within nomatch, I should get no match", func() {
			ip := net.ParseIP("10.10.10.100")
			port := uint16(443)
			_, _, err := c.GetMatchingAction(ip.To4(), port, packet.IPProtocolTCP, catchAllPolicy)
			So(err, ShouldNotBeNil)
		})

		Convey("When I lookup address within nomatch outer and not also within match inner, I should get no match", func() {
			ip := net.ParseIP("10.4.10.100")
			port := uint16(443)
			_, _, err := c.GetMatchingAction(ip.To4(), port, packet.IPProtocolTCP, catchAllPolicy)
			So(err, ShouldNotBeNil)
		})

		Convey("When I lookup address within match outer and not also within match inner, I should get accept", func() {
			ip := net.ParseIP("192.168.10.100")
			port := uint16(443)
			a, p, err := c.GetMatchingAction(ip.To4(), port, packet.IPProtocolTCP, catchAllPolicy)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Accept)
			So(p.Action, ShouldEqual, policy.Accept)
		})
	})
}

func TestRemoveRules(t *testing.T) {

	Convey("Given an ACL Cache with some rules", t, func() {
		ip := net.ParseIP("172.1.0.0")
		So(ip, ShouldNotBeNil)
		c := NewACLCache()
		So(c, ShouldNotBeNil)
		err := c.AddRuleList(policy.IPRuleList{
			policy.IPRule{
				Addresses: []string{"172.1.0.0/16"},
				Ports:     []string{"1"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					Action:   policy.Reject,
					PolicyID: "reject",
				},
			},
			policy.IPRule{
				Addresses: []string{"172.1.0.0/16"},
				Ports:     []string{"1"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					ObserveAction: policy.ObserveApply,
					PolicyID:      "observeApply",
				},
			},
			policy.IPRule{
				Addresses: []string{"172.1.0.0/16"},
				Ports:     []string{"1"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "accept",
				},
			},
		})
		So(err, ShouldBeNil)
		val, ok := c.reject.tcpCache.Get(ip, 16)
		So(ok, ShouldBeTrue)
		So(val.(portActionList), ShouldNotBeEmpty)
		val, ok = c.observe.tcpCache.Get(ip, 16)
		So(ok, ShouldBeTrue)
		So(val.(portActionList), ShouldNotBeEmpty)
		val, ok = c.accept.tcpCache.Get(ip, 16)
		So(ok, ShouldBeTrue)
		So(val.(portActionList), ShouldNotBeEmpty)

		Convey("Then I should error if I pass unparseable rules", func() {
			err := c.RemoveRulesForAddress(
				&Address{IP: ip, Mask: 16, NoMatch: false},
				constants.TCPProtoNum,
				[]string{"invalid"},
				&policy.FlowPolicy{
					Action:   policy.Reject,
					PolicyID: "reject",
				},
			)
			So(err, ShouldNotBeNil)
		})

		Convey("Then I should be able to remove the rules", func() {
			err := c.RemoveRulesForAddress(
				&Address{IP: ip, Mask: 16, NoMatch: false},
				constants.TCPProtoNum,
				[]string{"1"},
				&policy.FlowPolicy{
					Action:   policy.Reject,
					PolicyID: "reject",
				},
			)
			So(err, ShouldBeNil)
			err = c.RemoveRulesForAddress(
				&Address{IP: ip, Mask: 16, NoMatch: false},
				constants.TCPProtoNum,
				[]string{"1"},
				&policy.FlowPolicy{
					ObserveAction: policy.ObserveApply,
					PolicyID:      "observeApply",
				},
			)
			So(err, ShouldBeNil)
			err = c.RemoveRulesForAddress(
				&Address{IP: ip, Mask: 16, NoMatch: false},
				constants.TCPProtoNum,
				[]string{"1"},
				&policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "accept",
				},
			)
			So(err, ShouldBeNil)
			val, ok := c.reject.tcpCache.Get(ip, 16)
			So(ok, ShouldBeTrue)
			So(val.(portActionList), ShouldBeEmpty)
			val, ok = c.observe.tcpCache.Get(ip, 16)
			So(ok, ShouldBeTrue)
			So(val.(portActionList), ShouldBeEmpty)
			val, ok = c.accept.tcpCache.Get(ip, 16)
			So(ok, ShouldBeTrue)
			So(val.(portActionList), ShouldBeEmpty)
		})

	})
}
