// +build !windows

package portspec

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestNewPortSpec(t *testing.T) {
	Convey("When I create a new port spec", t, func() {
		p, err := NewPortSpec(0, 10, "portspec")
		So(err, ShouldBeNil)
		Convey("The correct values must be set", func() {
			So(p, ShouldNotBeNil)
			So(p.Min, ShouldEqual, 0)
			So(p.Max, ShouldEqual, 10)
			So(p.value.(string), ShouldResemble, "portspec")
		})
	})
}
func TestNewPortSpecFromString(t *testing.T) {
	Convey("When I create a valid single port spec from string it should succeed", t, func() {
		p, err := NewPortSpecFromString("10", "string")
		So(err, ShouldBeNil)
		So(p.Min, ShouldEqual, uint16(10))
		So(p.Max, ShouldEqual, uint16(10))
		So(p.value.(string), ShouldResemble, "string")
	})

	Convey("When I create a valid a range  port spec from string it should succeed", t, func() {
		p, err := NewPortSpecFromString("10:20", "string")
		So(err, ShouldBeNil)
		So(p.Min, ShouldEqual, uint16(10))
		So(p.Max, ShouldEqual, uint16(20))
		So(p.value.(string), ShouldResemble, "string")
	})

	Convey("When I create singe port with value greater than 2^16 it shoud fail ", t, func() {
		_, err := NewPortSpecFromString("70000", "string")
		So(err, ShouldNotBeNil)
	})

	Convey("When I create singe port with a negative value it should fail", t, func() {
		_, err := NewPortSpecFromString("-1", "string")
		So(err, ShouldNotBeNil)
	})

	Convey("When I create a range with min > max it shoud fail", t, func() {
		_, err := NewPortSpecFromString("20:10", "string")
		So(err, ShouldNotBeNil)
	})

	Convey("When I create a range with negative min or max  it shoud fail", t, func() {
		_, err := NewPortSpecFromString("-20:10", "string")
		So(err, ShouldNotBeNil)
		_, err = NewPortSpecFromString("-20:-110", "string")
		So(err, ShouldNotBeNil)
	})

	Convey("When I create a range with invalid characters it should fail", t, func() {
		_, err := NewPortSpecFromString("10,20", "string")
		So(err, ShouldNotBeNil)
	})
}

func TestIsMultiPort(t *testing.T) {
	Convey("Given a portspec", t, func() {
		s, err := NewPortSpecFromString("10:20", "string")
		So(err, ShouldBeNil)
		Convey("multiport should return true", func() {
			So(s.IsMultiPort(), ShouldBeTrue)
		})
	})
}

func TestRange(t *testing.T) {
	Convey("Given a portspec", t, func() {
		Convey("If it is multiport", func() {
			s, err := NewPortSpecFromString("10:20", "string")
			So(err, ShouldBeNil)
			Convey("Range  should return the value ranges", func() {
				min, max := s.Range()
				So(min, ShouldEqual, 10)
				So(max, ShouldEqual, 20)
			})
		})

		Convey("If it is not multiport, it should return the one port", func() {
			s, err := NewPortSpecFromString("10", "string")
			So(err, ShouldBeNil)
			Convey("Multiport should an error", func() {
				min, max := s.Range()
				So(min, ShouldEqual, 10)
				So(max, ShouldEqual, 10)
			})
		})
	})
}

func TestSinglePort(t *testing.T) {
	Convey("Given a portspec", t, func() {
		Convey("If it is singleport", func() {
			s, err := NewPortSpecFromString("10", "string")
			So(err, ShouldBeNil)
			Convey("Multiport should return the value ranges", func() {
				m, err := s.SinglePort()
				So(err, ShouldBeNil)
				So(m, ShouldEqual, uint16(10))
			})
		})

		Convey("If it is not multiport", func() {
			s, err := NewPortSpecFromString("10:20", "string")
			So(err, ShouldBeNil)
			Convey("Singleport  should an error", func() {
				_, err := s.SinglePort()
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestValue(t *testing.T) {
	Convey("Given a portspec, value should return the correct value", t, func() {
		s, err := NewPortSpecFromString("10:20", "value")
		So(err, ShouldBeNil)
		So(s.value.(string), ShouldResemble, "value")
	})
}

func TestOVerlap(t *testing.T) {
	Convey("Given two portspecs that don't overlap", t, func() {
		a, err1 := NewPortSpecFromString("10:20", "value")
		b, err2 := NewPortSpecFromString("30:40", "value")
		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)
		Convey("I should get false", func() {
			So(a.Overlaps(b), ShouldBeFalse)
		})
	})

	Convey("Given two portspecs that overlap", t, func() {
		a, err1 := NewPortSpecFromString("10:50", "value")
		b, err2 := NewPortSpecFromString("30:40", "value")
		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)
		Convey("I should get true", func() {
			So(a.Overlaps(b), ShouldBeTrue)
		})
	})

	Convey("Given two portspecs that partially overlap", t, func() {
		a, err1 := NewPortSpecFromString("10:35", "value")
		b, err2 := NewPortSpecFromString("30:40", "value")
		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)
		Convey("I should get true", func() {
			So(a.Overlaps(b), ShouldBeTrue)
		})
	})

	Convey("Given two portspecs that partially overlap at the end", t, func() {
		a, err1 := NewPortSpecFromString("35:45", "value")
		b, err2 := NewPortSpecFromString("30:40", "value")
		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)
		Convey("I should get true", func() {
			So(a.Overlaps(b), ShouldBeTrue)
		})
	})

	Convey("Given two portspecs that partially overlap at a point", t, func() {
		a, err1 := NewPortSpecFromString("10:20", "value")
		b, err2 := NewPortSpecFromString("10", "value")
		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)
		Convey("I should get true", func() {
			So(a.Overlaps(b), ShouldBeTrue)
		})
	})

	Convey("Given two portspecs that partially overlap at the end point", t, func() {
		a, err1 := NewPortSpecFromString("10:20", "value")
		b, err2 := NewPortSpecFromString("20", "value")
		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)
		Convey("I should get true", func() {
			So(a.Overlaps(b), ShouldBeTrue)
		})
	})

	Convey("Given two poit portspecs that overlap", t, func() {
		a, err1 := NewPortSpecFromString("20", "value")
		b, err2 := NewPortSpecFromString("20", "value")
		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)
		Convey("I should get true", func() {
			So(a.Overlaps(b), ShouldBeTrue)
		})
	})

	Convey("Given two poit portspecs that do not overlap", t, func() {
		a, err1 := NewPortSpecFromString("80", "value")
		b, err2 := NewPortSpecFromString("443", "value")
		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)
		Convey("I should get true", func() {
			So(a.Overlaps(b), ShouldBeFalse)
		})
	})
}
