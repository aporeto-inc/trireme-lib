// +build !windows

package servicecache

import (
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/utils/portspec"
)

func TestEntries(t *testing.T) {
	Convey("Given an entry list", t, func() {

		Convey("If I delete the last element, I should the right data", func() {
			e := entryList{
				{
					id: "1",
				},
				{
					id: "2",
				},
				{
					id: "3",
				},
				{
					id: "4",
				},
			}
			new := e.Delete(3)
			So(len(new), ShouldEqual, 3)
			So(new[0], ShouldResemble, &entry{id: "1"})
			So(new[1], ShouldResemble, &entry{id: "2"})
			So(new[2], ShouldResemble, &entry{id: "3"})
		})

		Convey("If I delete the first element in the list, I should get the right data", func() {
			e := entryList{
				{
					id: "1",
				},
				{
					id: "2",
				},
				{
					id: "3",
				},
			}
			new := e.Delete(0)
			So(len(new), ShouldEqual, 2)
			So(new[0], ShouldResemble, &entry{id: "2"})
			So(new[1], ShouldResemble, &entry{id: "3"})
		})

		Convey("If I try to delete out of bounds, the list should not be modified", func() {
			e := entryList{
				{
					id: "1",
				},
				{
					id: "3",
				},
			}
			new := e.Delete(4)
			So(len(new), ShouldEqual, 2)
			So(new[0], ShouldResemble, &entry{id: "1"})
			So(new[1], ShouldResemble, &entry{id: "3"})
		})
		Convey("If I delete the last element list I should get an empty list", func() {
			e := entryList{
				{
					id: "1",
				},
			}
			new := e.Delete(0)
			So(len(new), ShouldEqual, 0)
		})
	})
}

func createServices() (*common.Service, *common.Service, *common.Service) {
	n1 := "172.17.1.0/24"
	n2 := "192.168.0.0/16"
	n3 := "20.1.1.1/32"

	s1 := &common.Service{
		Ports: &portspec.PortSpec{
			Min: uint16(0),
			Max: uint16(100),
		},
		Protocol:  6,
		Addresses: map[string]struct{}{n1: struct{}{}, n2: struct{}{}, n3: struct{}{}},
		FQDNs:     []string{"host1", "host2", "host3"},
	}

	n4 := "10.1.1.0/28"

	s2 := &common.Service{
		Ports: &portspec.PortSpec{
			Min: uint16(150),
			Max: uint16(200),
		},
		Protocol:  6,
		Addresses: map[string]struct{}{n4: struct{}{}},
		FQDNs:     []string{"host4"},
	}

	s3 := &common.Service{
		Ports: &portspec.PortSpec{
			Min: uint16(1000),
			Max: uint16(2000),
		},
		Protocol:  6,
		Addresses: map[string]struct{}{},
	}

	return s1, s2, s3
}
func TestServiceCache(t *testing.T) {
	Convey("Given a new cache", t, func() {
		c := NewTable()
		Convey("When I add a set of entries, I should succeed", func() {

			s1, s2, s3 := createServices()

			cerr := c.Add(s1, "1", "first data", true)
			So(cerr, ShouldBeNil)
			So(c.local, ShouldNotBeNil)
			So(c.localHosts, ShouldNotBeNil)
			So(len(c.localHosts), ShouldEqual, 3)

			cerr = c.Add(s2, "2", "second data", true)
			So(cerr, ShouldBeNil)
			So(c.local, ShouldNotBeNil)
			So(c.localHosts, ShouldNotBeNil)
			So(len(c.localHosts), ShouldEqual, 4)

			cerr = c.Add(s3, "3", "third data", true)
			So(cerr, ShouldBeNil)
			So(len(c.localHosts), ShouldEqual, 4)

		})

		Convey("If I try to add overlapping ports for a given prefix, I should get error", func() {
			s1, s2, s3 := createServices()
			cerr := c.Add(s1, "1", "first data", true)
			So(cerr, ShouldBeNil)
			cerr = c.Add(s2, "2", "second data", true)
			So(cerr, ShouldBeNil)
			cerr = c.Add(s3, "3", "third data", true)
			So(cerr, ShouldBeNil)

			n5 := "10.1.1.0/28"
			s4 := &common.Service{
				Ports: &portspec.PortSpec{
					Min: uint16(100),
					Max: uint16(300),
				},
				Protocol:  6,
				Addresses: map[string]struct{}{n5: struct{}{}},
			}
			cerr = c.Add(s4, "4", "failed data", true)
			So(cerr, ShouldNotBeNil)
		})

		Convey("If I try to add overlapping ports for a given host, I should get error", func() {
			s1, s2, s3 := createServices()
			cerr := c.Add(s1, "1", "first data", true)
			So(cerr, ShouldBeNil)
			cerr = c.Add(s2, "2", "second data", true)
			So(cerr, ShouldBeNil)
			cerr = c.Add(s3, "3", "third data", true)
			So(cerr, ShouldBeNil)

			s4 := &common.Service{
				Ports: &portspec.PortSpec{
					Min: uint16(100),
					Max: uint16(300),
				},
				Protocol:  6,
				Addresses: nil,
				FQDNs:     []string{"host4"},
			}
			cerr = c.Add(s4, "4", "failed data", true)
			So(cerr, ShouldNotBeNil)
		})

		Convey("When I search for valid entries, I should get the right responses", func() {
			s1, s2, s3 := createServices()
			cerr := c.Add(s1, "1", "first data", true)
			So(cerr, ShouldBeNil)
			cerr = c.Add(s2, "2", "second data", true)
			So(cerr, ShouldBeNil)
			cerr = c.Add(s3, "3", "third data", true)
			So(cerr, ShouldBeNil)

			data := c.Find(net.ParseIP("10.1.1.1").To4(), 175, "", true)
			So(data, ShouldNotBeNil)
			So(data.(string), ShouldResemble, "second data")

			data = c.Find(net.ParseIP("192.168.1.1").To4(), 50, "", true)
			So(data, ShouldNotBeNil)
			So(data.(string), ShouldResemble, "first data")

			data = c.Find(net.ParseIP("50.50.50.50").To4(), 1001, "", true)
			So(data, ShouldNotBeNil)
			So(data.(string), ShouldResemble, "third data")

			data = c.Find(nil, 50, "host2", true)
			So(data, ShouldNotBeNil)
			So(data.(string), ShouldResemble, "first data")

			data = c.Find(nil, 150, "host4", true)
			So(data, ShouldNotBeNil)
			So(data.(string), ShouldResemble, "second data")
		})

		Convey("When I search for a good IP, but invalid port, I should get nil ", func() {
			s1, s2, s3 := createServices()
			cerr := c.Add(s1, "1", "first data", true)
			So(cerr, ShouldBeNil)
			cerr = c.Add(s2, "2", "second data", true)
			So(cerr, ShouldBeNil)
			cerr = c.Add(s3, "3", "third data", true)
			So(cerr, ShouldBeNil)

			data := c.Find(net.ParseIP("10.1.1.1").To4(), 50, "", true)
			So(data, ShouldBeNil)
		})

		Convey("When I search for a good IP, but uknown host, I should get nil ", func() {
			s1, s2, s3 := createServices()
			cerr := c.Add(s1, "1", "first data", true)
			So(cerr, ShouldBeNil)
			cerr = c.Add(s2, "2", "second data", true)
			So(cerr, ShouldBeNil)
			cerr = c.Add(s3, "3", "third data", true)
			So(cerr, ShouldBeNil)

			data := c.Find(nil, 50, "uknown", true)
			So(data, ShouldBeNil)
		})

		Convey("When I search for a good IP, but invalid host, I should get nil ", func() {
			s1, s2, s3 := createServices()
			cerr := c.Add(s1, "1", "first data", true)
			So(cerr, ShouldBeNil)
			cerr = c.Add(s2, "2", "second data", true)
			So(cerr, ShouldBeNil)
			cerr = c.Add(s3, "3", "third data", true)
			So(cerr, ShouldBeNil)

			data := c.Find(nil, 50, "host4", true)
			So(data, ShouldBeNil)
		})

		Convey("When I search for a good exact IP, and valid port, I should get the data ", func() {
			s1, s2, s3 := createServices()
			cerr := c.Add(s1, "1", "first data", true)
			So(cerr, ShouldBeNil)
			cerr = c.Add(s2, "2", "second data", true)
			So(cerr, ShouldBeNil)
			cerr = c.Add(s3, "3", "third data", true)
			So(cerr, ShouldBeNil)

			data := c.Find(net.ParseIP("20.1.1.1").To4(), 50, "", true)
			So(data, ShouldNotBeNil)
			So(data.(string), ShouldResemble, "first data")
		})
	})
}

func TestDelete(t *testing.T) {
	Convey("When I delete the first of entries, I should not be able to find them any more", t, func() {
		c := NewTable()
		s1, s2, s3 := createServices()
		cerr := c.Add(s1, "1", "first data", true)
		So(cerr, ShouldBeNil)
		cerr = c.Add(s2, "2", "second data", true)
		So(cerr, ShouldBeNil)
		cerr = c.Add(s3, "3", "third data", false)
		So(cerr, ShouldBeNil)

		c.DeleteByID("1", true)
		data := c.Find(net.ParseIP("192.168.1.1").To4(), 50, "", true)
		So(data, ShouldBeNil)
	})
}

func TestFindExistingServices(t *testing.T) {
	Convey("Given a table with entries", t, func() {
		c := NewTable()
		s1, s2, s3 := createServices()
		cerr := c.Add(s1, "1", "first data", true)
		So(cerr, ShouldBeNil)
		cerr = c.Add(s2, "2", "second data", true)
		So(cerr, ShouldBeNil)
		cerr = c.Add(s3, "3", "third data", true)
		So(cerr, ShouldBeNil)

		Convey("When I retrieve the service list from the local, it should be correct", func() {
			data, spec := c.FindListeningServicesForPU("3")
			So(data, ShouldNotBeNil)
			So(data, ShouldResemble, "third data")
			So(spec, ShouldNotBeNil)
		})
	})
}
