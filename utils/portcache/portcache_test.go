package portcache

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/utils/portspec"
)

func TestNewPortCache(t *testing.T) {
	Convey("When I creat a new port cache", t, func() {
		p := NewPortCache("test")
		Convey("The cache must be initilized", func() {
			So(p, ShouldNotBeNil)
			So(p.ports, ShouldNotBeNil)
			So(p.ranges, ShouldNotBeNil)
		})
	})
}

func TestAddPortSpec(t *testing.T) {
	Convey("Given an initialized cached", t, func() {
		p := NewPortCache("test")
		Convey("When I add a port spec with a single port, it must added to the map", func() {
			s, err := portspec.NewPortSpec(10, 10, "10")
			So(err, ShouldBeNil)
			p.AddPortSpec(s)
			stored, err := p.ports.Get(uint16(10))
			So(err, ShouldBeNil)
			So(stored.(*portspec.PortSpec), ShouldNotBeNil)
			So(stored.(*portspec.PortSpec).Max, ShouldEqual, 10)
			So(stored.(*portspec.PortSpec).Min, ShouldEqual, 10)
			So(stored.(*portspec.PortSpec).Value().(string), ShouldResemble, "10")
		})

		Convey("When I add a port spec with a range of ports, be added to the list", func() {
			s, err := portspec.NewPortSpec(10, 20, "range")
			So(err, ShouldBeNil)
			p.AddPortSpec(s)
			So(len(p.ranges), ShouldEqual, 1)
			So(p.ranges[0].Min, ShouldEqual, 10)
			So(p.ranges[0].Max, ShouldEqual, 20)
			So(p.ranges[0].Value().(string), ShouldResemble, "range")
		})
	})
}

func TestSearch(t *testing.T) {
	Convey("Given an initialized cache", t, func() {
		p := NewPortCache("test")
		Convey("When I add both single ports and rages", func() {
			s, err := portspec.NewPortSpec(10, 20, "range1")
			So(err, ShouldBeNil)
			p.AddPortSpec(s)

			s, err = portspec.NewPortSpec(30, 40, "range2")
			So(err, ShouldBeNil)
			p.AddPortSpec(s)

			s, err = portspec.NewPortSpec(50, 60, "range3")
			So(err, ShouldBeNil)
			p.AddPortSpec(s)

			s, err = portspec.NewPortSpec(15, 15, "15")
			So(err, ShouldBeNil)
			p.AddPortSpec(s)

			s, err = portspec.NewPortSpec(25, 25, "25")
			So(err, ShouldBeNil)
			p.AddPortSpec(s)

			Convey("If I match both exact and range, I should get the exact", func() {
				s, err := p.GetSpecValueFromPort(15)
				So(err, ShouldBeNil)
				So(s.(string), ShouldResemble, "15")
				s, err = p.GetSpecValueFromPort(25)
				So(err, ShouldBeNil)
				So(s.(string), ShouldResemble, "25")
			})

			Convey("If I match the range beginning, I should get the result", func() {
				s, err := p.GetSpecValueFromPort(10)
				So(err, ShouldBeNil)
				So(s.(string), ShouldResemble, "range1")
			})

			Convey("If I match the range end , I should get the result", func() {
				s, err := p.GetSpecValueFromPort(19)
				So(err, ShouldBeNil)
				So(s.(string), ShouldResemble, "range1")
				s, err = p.GetSpecValueFromPort(39)
				So(err, ShouldBeNil)
				So(s.(string), ShouldResemble, "range2")
				s, err = p.GetSpecValueFromPort(59)
				So(err, ShouldBeNil)
				So(s.(string), ShouldResemble, "range3")
			})

			Convey("Last number is included ", func() {
				_, err := p.GetSpecValueFromPort(20)
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestGetAll(t *testing.T) {
	Convey("Given an initialized cache", t, func() {
		p := NewPortCache("test")
		Convey("When I add both single ports and rages", func() {
			s, err := portspec.NewPortSpec(10, 20, "range1")
			So(err, ShouldBeNil)
			p.AddPortSpec(s)

			s, err = portspec.NewPortSpec(30, 40, "range2")
			So(err, ShouldBeNil)
			p.AddPortSpec(s)

			s, err = portspec.NewPortSpec(50, 60, "range3")
			So(err, ShouldBeNil)
			p.AddPortSpec(s)

			s, err = portspec.NewPortSpec(15, 15, "15")
			So(err, ShouldBeNil)
			p.AddPortSpec(s)

			s, err = portspec.NewPortSpec(25, 25, "25")
			So(err, ShouldBeNil)
			p.AddPortSpec(s)

			Convey("If I match both exact and range, I should get the exact", func() {
				s, err := p.GetAllSpecValueFromPort(15)
				So(err, ShouldBeNil)
				So(len(s), ShouldEqual, 2)

				So(s[0].(string), ShouldResemble, "15")
				So(s[1].(string), ShouldResemble, "range1")
			})
		})
	})
}

func TestAddUnique(t *testing.T) {
	Convey("Given an initialized cache", t, func() {
		p := NewPortCache("test")
		Convey("When I add unique entries, I should get no errors ", func() {
			s, err := portspec.NewPortSpec(10, 20, "range1")
			So(err, ShouldBeNil)
			So(p.AddUnique(s), ShouldBeNil)

			s, err = portspec.NewPortSpec(30, 40, "range2")
			So(err, ShouldBeNil)
			So(p.AddUnique(s), ShouldBeNil)

			s, err = portspec.NewPortSpec(50, 60, "range3")
			So(err, ShouldBeNil)
			So(p.AddUnique(s), ShouldBeNil)
		})

		Convey("When I add non-unique entries, I should get  errors ", func() {
			s, err := portspec.NewPortSpec(10, 20, "range1")
			So(err, ShouldBeNil)
			So(p.AddUnique(s), ShouldBeNil)

			s, err = portspec.NewPortSpec(30, 40, "range1")
			So(err, ShouldBeNil)
			So(p.AddUnique(s), ShouldBeNil)

			s, err = portspec.NewPortSpec(5, 15, "range2")
			So(err, ShouldBeNil)
			So(p.AddUnique(s), ShouldNotBeNil)

			s, err = portspec.NewPortSpec(15, 25, "range2")
			So(err, ShouldBeNil)
			So(p.AddUnique(s), ShouldNotBeNil)

			s, err = portspec.NewPortSpec(5, 25, "range3")
			So(err, ShouldBeNil)
			So(p.AddUnique(s), ShouldNotBeNil)

			s, err = portspec.NewPortSpec(5, 5, "range3")
			So(err, ShouldBeNil)
			So(p.AddUnique(s), ShouldBeNil)

			s, err = portspec.NewPortSpec(15, 15, "range3")
			So(err, ShouldBeNil)
			So(p.AddUnique(s), ShouldNotBeNil)

			s, err = portspec.NewPortSpec(25, 25, "range3")
			So(err, ShouldBeNil)
			So(p.AddUnique(s), ShouldBeNil)
		})

		Convey("When I match error'd unique entries and a valid range, I should get the valid range only", func() {
			s, err := portspec.NewPortSpec(10, 20, "range1")
			So(err, ShouldBeNil)
			So(p.AddUnique(s), ShouldBeNil)

			s, err = portspec.NewPortSpec(5, 15, "range2")
			So(err, ShouldBeNil)
			So(p.AddUnique(s), ShouldNotBeNil)

			s, err = portspec.NewPortSpec(15, 15, "15")
			So(err, ShouldBeNil)
			So(p.AddUnique(s), ShouldNotBeNil)

			a, err := p.GetAllSpecValueFromPort(15)
			So(err, ShouldBeNil)
			So(len(a), ShouldEqual, 1)
			So(a[0].(string), ShouldResemble, "range1")
		})
	})
}

func TestRemoveStringPort(t *testing.T) {
	Convey("Given an initialized cache", t, func() {
		p := NewPortCache("test")

		s, err := portspec.NewPortSpec(10, 20, "range1")
		So(err, ShouldBeNil)
		So(p.AddUnique(s), ShouldBeNil)

		s, err = portspec.NewPortSpec(30, 40, "range2")
		So(err, ShouldBeNil)
		So(p.AddUnique(s), ShouldBeNil)

		s, err = portspec.NewPortSpec(100, 100, "range3")
		So(err, ShouldBeNil)
		So(p.AddUnique(s), ShouldBeNil)

		Convey("When I remove valid entries, there should be no errors", func() {
			So(p.RemoveStringPorts("10:20"), ShouldBeNil)
			So(p.RemoveStringPorts("30:40"), ShouldBeNil)
			So(p.RemoveStringPorts("100:100"), ShouldBeNil)
		})

		Convey("When I remove invalid entries, I should get an error", func() {
			So(p.RemoveStringPorts("100:200"), ShouldNotBeNil)
			So(p.RemoveStringPorts("10:40"), ShouldNotBeNil)
		})
	})
}
