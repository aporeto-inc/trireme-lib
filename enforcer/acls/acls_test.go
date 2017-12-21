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
			Address:  "172.17.0.0/16",
			Port:     "400:500",
			Protocol: "tcp",
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "1"},
		},
		policy.IPRule{
			Address:  "192.168.100.0/24",
			Protocol: "tcp",
			Port:     "80",
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "2"},
		},
		policy.IPRule{
			Address:  "10.1.1.1",
			Protocol: "tcp",
			Port:     "80",
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "3"}},
		policy.IPRule{
			Address:  "0.0.0.0/0",
			Protocol: "tcp",
			Port:     "443",
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "4"}},
		policy.IPRule{
			Address:  "0.0.0.0/0",
			Protocol: "udp",
			Port:     "443",
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "5"}},
	}
)

func TestLookup(t *testing.T) {

	Convey("Given a good DB", t, func() {
		c := NewACLCache()
		err := c.AddRuleList(rules)
		So(err, ShouldBeNil)
		So(len(c.prefixMap), ShouldEqual, len(rules)-1)

		Convey("When I lookup for a matching address and a port range, I should get the right action", func() {
			ip := net.ParseIP("172.17.0.1")
			port := uint16(401)
			r, a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Accept)
			So(r.Action, ShouldEqual, policy.Accept)
		})

		Convey("When I lookup for a matching address exact port, I should get the right action", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(80)
			r, a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Accept)
			So(r.Action, ShouldEqual, policy.Accept)
		})

		Convey("When I lookup for a non matching address . I should get reject", func() {
			ip := net.ParseIP("192.168.200.1")
			port := uint16(80)
			r, a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldNotBeNil)
			So(a.Action, ShouldEqual, policy.Reject)
			So(r.Action, ShouldEqual, policy.Reject)
		})

		Convey("When I lookup for a matching address but failed port, I should get reject", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(600)
			r, a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldNotBeNil)
			So(a.Action, ShouldEqual, policy.Reject)
			So(r.Action, ShouldEqual, policy.Reject)
		})

		Convey("When I lookup for a matching exact address exact port, I should get the right action", func() {
			ip := net.ParseIP("10.1.1.1")
			port := uint16(80)
			r, a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a.Action, ShouldEqual, policy.Accept)
			So(r.Action, ShouldEqual, policy.Accept)
		})
	})
}
