package acls

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/v11/policy"
)

func TestEmptyPortListLookup(t *testing.T) {

	Convey("Given an empty port action list", t, func() {
		pl := &portActionList{}

		Convey("When I lookup for a matching port, I should not get any result", func() {
			r, p, err := pl.lookup(10, nil)
			So(err, ShouldNotBeNil)
			So(r, ShouldBeNil)
			So(p, ShouldBeNil)
		})
	})
}

func TestPortListLookup(t *testing.T) {

	rule := policy.IPRule{
		Addresses: []string{"172.0.0.0/8"},
		Ports:     []string{"1:999"},
		Protocols: []string{"tcp"},
		Policy: &policy.FlowPolicy{
			Action:   policy.Accept,
			PolicyID: "portMatch",
		},
	}

	Convey("Given a non-empty port action list", t, func() {
		var pl portActionList
		for _, port := range rule.Ports {
			pa, err := newPortAction(port, rule.Policy)

			So(err, ShouldBeNil)
			So(pa, ShouldNotBeNil)

			pl = append(pl, pa)
		}

		Convey("When I lookup for a non matching port, I should get error", func() {
			r, p, err := pl.lookup(0, nil)
			So(err, ShouldNotBeNil)
			So(r, ShouldBeNil)
			So(p, ShouldBeNil)
		})

		Convey("When I lookup for a non matching port, I should get error but get the unmodified reported flow input", func() {
			r, p, err := pl.lookup(0, &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "portPreMatch"},
			)
			So(err, ShouldNotBeNil)
			So(r, ShouldNotBeNil)
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "portPreMatch")
			So(p, ShouldBeNil)
		})

		Convey("When I lookup for a matching port, I should get accept", func() {
			r, p, err := pl.lookup(10, nil)
			So(err, ShouldBeNil)
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "portMatch")
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "portMatch")
		})

		Convey("When I lookup for a matching port, and a report action, packet must be reported with no error", func() {
			r, p, err := pl.lookup(10, &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "portPreMatch"},
			)
			So(err, ShouldBeNil)
			So(r, ShouldNotBeNil)
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "portPreMatch")
			So(p, ShouldNotBeNil)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "portMatch")
		})
	})
}

func TestPortListLookupObservedPolicyContinue(t *testing.T) {

	rule := policy.IPRule{
		Addresses: []string{"172.0.0.0/8"},
		Ports:     []string{"1:999"},
		Protocols: []string{"tcp"},
		Policy: &policy.FlowPolicy{
			ObserveAction: policy.ObserveContinue,
			Action:        policy.Accept,
			PolicyID:      "portMatch",
		},
	}

	Convey("Given a non-empty port action list", t, func() {
		var pl portActionList
		for _, port := range rule.Ports {
			pa, err := newPortAction(port, rule.Policy)
			So(err, ShouldBeNil)
			So(pa, ShouldNotBeNil)

			pl = append(pl, pa)
		}

		Convey("When I lookup for a non matching port, I should get error", func() {
			r, p, err := pl.lookup(0, nil)
			So(err, ShouldNotBeNil)
			So(r, ShouldBeNil)
			So(p, ShouldBeNil)
		})

		Convey("When I lookup for a non matching port, I should get error but get the unmodified reported flow input", func() {
			r, p, err := pl.lookup(0, &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "portPreMatch"},
			)
			So(err, ShouldNotBeNil)
			So(r, ShouldNotBeNil)
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "portPreMatch")
			So(p, ShouldBeNil)
		})

		Convey("When I lookup for a matching port with observed policy, I should get report but no packet action and error ", func() {
			r, p, err := pl.lookup(10, nil)
			So(err, ShouldEqual, ErrNoMatch)
			So(r.ObserveAction, ShouldEqual, policy.ObserveContinue)
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "portMatch")
			So(p, ShouldBeNil)
		})

		Convey("When I lookup for a matching port with observed policy and pre-existing report, I should get unmodified report but no packet action and error ", func() {
			r, p, err := pl.lookup(10, &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "portPreMatch",
			})
			So(err, ShouldEqual, ErrNoMatch)
			So(r.ObserveAction, ShouldEqual, policy.ObserveNone)
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "portPreMatch")
			So(p, ShouldBeNil)
		})
	})
}

func TestPortListLookupObservedPolicyApply(t *testing.T) {

	rule := policy.IPRule{
		Addresses: []string{"172.0.0.0/8"},
		Ports:     []string{"1:999"},
		Protocols: []string{"tcp"},
		Policy: &policy.FlowPolicy{
			ObserveAction: policy.ObserveApply,
			Action:        policy.Accept,
			PolicyID:      "portMatch",
		},
	}

	Convey("Given a non-empty port action list", t, func() {
		var pl portActionList
		for _, port := range rule.Ports {
			pa, err := newPortAction(port, rule.Policy)
			So(err, ShouldBeNil)
			So(pa, ShouldNotBeNil)

			pl = append(pl, pa)
		}

		Convey("When I lookup for a non matching port, I should get error", func() {
			r, p, err := pl.lookup(0, nil)
			So(err, ShouldNotBeNil)
			So(r, ShouldBeNil)
			So(p, ShouldBeNil)
		})

		Convey("When I lookup for a non matching port, I should get error but get the unmodified reported flow input", func() {
			r, p, err := pl.lookup(0, &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "portPreMatch"},
			)
			So(err, ShouldNotBeNil)
			So(r, ShouldNotBeNil)
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "portPreMatch")
			So(p, ShouldBeNil)
		})

		Convey("When I lookup for a matching port with observed policy apply, I should get report and packet action and no error ", func() {
			r, p, err := pl.lookup(10, nil)

			So(err, ShouldBeNil)

			So(r.ObserveAction, ShouldEqual, policy.ObserveApply)
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "portMatch")

			So(p.ObserveAction, ShouldEqual, policy.ObserveApply)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "portMatch")
		})

		Convey("When I lookup for a matching port with observed policy and pre-existing report, I should get unmodified report, packet action and no error ", func() {
			r, p, err := pl.lookup(10, &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "portPreMatch",
			})

			So(err, ShouldBeNil)

			So(r.ObserveAction, ShouldEqual, policy.ObserveNone)
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "portPreMatch")

			So(p.ObserveAction, ShouldEqual, policy.ObserveApply)
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "portMatch")
		})
	})
}
