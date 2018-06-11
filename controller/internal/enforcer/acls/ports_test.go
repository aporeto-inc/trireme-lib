package acls

import (
	"testing"

	"go.aporeto.io/trireme-lib/policy"
	. "github.com/smartystreets/goconvey/convey"
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
		Address:  "172.0.0.0/8",
		Port:     "1:999",
		Protocol: "tcp",
		Policy: &policy.FlowPolicy{
			Action:   policy.Accept,
			PolicyID: "portMatch"},
	}

	Convey("Given a non-empty port action list", t, func() {
		pa, err := newPortAction(rule)
		So(err, ShouldBeNil)
		So(pa, ShouldNotBeNil)

		pl := &portActionList{pa}

		Convey("When I lookup for a matching port, I should get accept", func() {
			r, p, err := pl.lookup(10, nil)
			So(err, ShouldBeNil)
			So(r.Action, ShouldEqual, policy.Accept)
			So(r.PolicyID, ShouldEqual, "portMatch")
			So(p.Action, ShouldEqual, policy.Accept)
			So(p.PolicyID, ShouldEqual, "portMatch")
		})

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
	})
}
