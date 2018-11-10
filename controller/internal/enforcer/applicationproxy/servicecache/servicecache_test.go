package servicecache

import (
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/utils/portspec"
)

func TestServiceCache(t *testing.T) {
	Convey("Given a new cache", t, func() {
		c := NewTable()
		Convey("When I add a set of entries, I should succeed", func() {
			_, n1, err1 := net.ParseCIDR("172.17.1.0/24")
			So(err1, ShouldBeNil)
			_, n2, err2 := net.ParseCIDR("192.168.0.0/16")
			So(err2, ShouldBeNil)
			_, n3, err3 := net.ParseCIDR("20.1.1.1/32")
			So(err3, ShouldBeNil)
			s1 := &common.Service{
				Ports: &portspec.PortSpec{
					Min: uint16(0),
					Max: uint16(100),
				},
				Protocol:  6,
				Addresses: []*net.IPNet{n1, n2, n3},
			}

			cerr := c.Add(s1, "first data", true)
			So(cerr, ShouldBeNil)
			So(c.local, ShouldNotBeNil)
			So(len(c.local), ShouldEqual, 3)

			_, n4, err4 := net.ParseCIDR("10.1.1.0/28")
			So(err4, ShouldBeNil)
			s2 := &common.Service{
				Ports: &portspec.PortSpec{
					Min: uint16(150),
					Max: uint16(200),
				},
				Protocol:  6,
				Addresses: []*net.IPNet{n4},
			}
			cerr = c.Add(s2, "second data", true)
			So(cerr, ShouldBeNil)
			So(c.local, ShouldNotBeNil)
			So(len(c.local), ShouldEqual, 4)

			s3 := &common.Service{
				Ports: &portspec.PortSpec{
					Min: uint16(1000),
					Max: uint16(2000),
				},
				Protocol:  6,
				Addresses: []*net.IPNet{},
			}
			cerr = c.Add(s3, "third data", true)
			So(cerr, ShouldBeNil)
			So(len(c.local), ShouldEqual, 5)

			Convey("If I try to add overlapping ports for a given prefix, I should get error", func() {
				_, n5, err5 := net.ParseCIDR("10.1.1.0/28")
				So(err5, ShouldBeNil)
				s3 := &common.Service{
					Ports: &portspec.PortSpec{
						Min: uint16(100),
						Max: uint16(300),
					},
					Protocol:  6,
					Addresses: []*net.IPNet{n5},
				}
				cerr = c.Add(s3, "second data", true)
				So(cerr, ShouldNotBeNil)
			})

			Convey("When I search for valid entries, I should get the right responses", func() {
				data := c.Find(net.ParseIP("10.1.1.1").To4(), 175, "", true)
				So(data, ShouldNotBeNil)
				So(data.(string), ShouldResemble, "second data")

				data = c.Find(net.ParseIP("192.168.1.1").To4(), 50, "", true)
				So(data, ShouldNotBeNil)
				So(data.(string), ShouldResemble, "first data")

				data = c.Find(net.ParseIP("50.50.50.50").To4(), 1001, "", true)
				So(data, ShouldNotBeNil)
				So(data.(string), ShouldResemble, "third data")
			})

			Convey("When I search for a good IP, but invalid port, I should get nil ", func() {
				data := c.Find(net.ParseIP("10.1.1.1").To4(), 50, "", true)
				So(data, ShouldBeNil)
			})

			Convey("When I search for a good exact IP, and valid port, I should get the data ", func() {
				data := c.Find(net.ParseIP("20.1.1.1").To4(), 50, "", true)
				So(data, ShouldNotBeNil)
				So(data.(string), ShouldResemble, "first data")
			})
		})
	})
}
