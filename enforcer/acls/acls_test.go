package acls

import (
	"net"
	"testing"

	"github.com/aporeto-inc/trireme/policy"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	rules = policy.IPRuleList{
		policy.IPRule{
			Address:  "172.17.0.0/16",
			Port:     "400:500",
			Protocol: "tcp",
			Action:   policy.Accept},
		policy.IPRule{
			Address:  "192.168.100.0/24",
			Protocol: "tcp",
			Port:     "80",
			Action:   policy.Accept},
		policy.IPRule{
			Address:  "10.1.1.1",
			Protocol: "tcp",
			Port:     "80",
			Action:   policy.Accept},
		policy.IPRule{
			Address:  "0.0.0.0/0",
			Protocol: "tcp",
			Port:     "443",
			Action:   policy.Accept},
		policy.IPRule{
			Address:  "0.0.0.0/0",
			Protocol: "udp",
			Port:     "443",
			Action:   policy.Accept},
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
			a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a, ShouldEqual, policy.Accept)
		})

		Convey("When I lookup for a matching address exact port, I should get the right action", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(80)
			a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a, ShouldEqual, policy.Accept)
		})

		Convey("When I lookup for a non matching address . I should get reject", func() {
			ip := net.ParseIP("192.168.200.1")
			port := uint16(80)
			a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldNotBeNil)
			So(a, ShouldEqual, policy.Reject)
		})

		Convey("When I lookup for a matching address but failed port, I should get reject", func() {
			ip := net.ParseIP("192.168.100.1")
			port := uint16(600)
			a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldNotBeNil)
			So(a, ShouldEqual, policy.Reject)
		})

		Convey("When I lookup for a matching exact address exact port, I should get the right action", func() {
			ip := net.ParseIP("10.1.1.1")
			port := uint16(80)
			a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a, ShouldEqual, policy.Accept)
		})

		Convey("When I lookup for a matching the 0.0.0.0/0 ACL, it shoud return succes ", func() {
			ip := net.ParseIP("23.24.23.24")
			port := uint16(443)
			a, err := c.GetMatchingAction(ip.To4(), port)
			So(err, ShouldBeNil)
			So(a, ShouldEqual, policy.Accept)
		})
	})
}
