// +build !windows

package acls

import (
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/policy"
)

func TestEmptyACLCacheLookup(t *testing.T) {

	Convey("Given an empty ACL Cache", t, func() {
		c := NewACLCache()
		Convey("When I lookup for a matching address but failed port, I should get reject", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(600)
			a, p, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldNotBeNil)
			So(a.Action, ShouldEqual, policy.Reject)
			So(a.PolicyID, ShouldEqual, "default")
			So(p.Action, ShouldEqual, policy.Reject)
			So(p.PolicyID, ShouldEqual, "default")
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
			a, p, err := c.GetMatchingAction(ip.To4(), port)
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
			a, p, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldNotBeNil)
			So(a.Action, ShouldEqual, policy.Accept)
			So(a.PolicyID, ShouldEqual, "ObserveAcceptContinue")
			So(p.Action, ShouldEqual, policy.Reject)
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
			a, p, err := c.GetMatchingAction(ip.To4(), port)
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
			a, p, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Reject)
			So(a.PolicyID, ShouldEqual, "observeRejectContinue-172.1/16")
			// So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp172/8")
		})

		Convey("When I lookup for a matching address to /8, I should get report reject and packet accept and ignore observe-apply rule", func() {
			ip := net.ParseIP("172.2.1.1")
			port := uint16(1)
			a, p, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Reject)
			So(a.PolicyID, ShouldEqual, "observeRejectContinue")
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "tcp172/8")
		})
	})
}
