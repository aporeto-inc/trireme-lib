package portspec

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestUncoveredPortRanges(t *testing.T) {

	Convey("When I create a range of port specs", t, func() {
		ports := []string{"55:66", "22", "100:500", "10", "99"}
		portSpecs := []*PortSpec{}
		for i := 0; i < len(ports); i++ {
			portSpec, _ := NewPortSpecFromString(ports[i], nil)
			portSpecs = append(portSpecs, portSpec)
		}
		ranges, err := GetUncoveredPortRanges(portSpecs...)

		Convey("Then result should match expected output", func() {
			expectedRanges := []*PortSpec{
				&PortSpec{Min: 1, Max: 9},
				&PortSpec{Min: 11, Max: 21},
				&PortSpec{Min: 23, Max: 54},
				&PortSpec{Min: 67, Max: 98},
				&PortSpec{Min: 501, Max: 65535},
			}

			So(ranges, ShouldResemble, expectedRanges)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I create a range of port specs with one of the element as last valid port", t, func() {
		ports := []string{"55:66", "65535", "100:500", "10", "99"}
		portSpecs := []*PortSpec{}
		for i := 0; i < len(ports); i++ {
			portSpec, _ := NewPortSpecFromString(ports[i], nil)
			portSpecs = append(portSpecs, portSpec)
		}
		ranges, err := GetUncoveredPortRanges(portSpecs...)

		Convey("Then result should match expected output", func() {
			expectedRanges := []*PortSpec{
				&PortSpec{Min: 1, Max: 9},
				&PortSpec{Min: 11, Max: 54},
				&PortSpec{Min: 67, Max: 98},
				&PortSpec{Min: 501, Max: 65534},
			}

			So(ranges, ShouldResemble, expectedRanges)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I create a range of port specs with one of the element as last valid port", t, func() {
		ports := []string{"55:66", "1", "100:500", "10", "99"}
		portSpecs := []*PortSpec{}
		for i := 0; i < len(ports); i++ {
			portSpec, _ := NewPortSpecFromString(ports[i], nil)
			portSpecs = append(portSpecs, portSpec)
		}
		ranges, err := GetUncoveredPortRanges(portSpecs...)

		Convey("Then result should match expected output", func() {
			expectedRanges := []*PortSpec{
				&PortSpec{Min: 2, Max: 9},
				&PortSpec{Min: 11, Max: 54},
				&PortSpec{Min: 67, Max: 98},
				&PortSpec{Min: 501, Max: 65535},
			}

			So(ranges, ShouldResemble, expectedRanges)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I create one range of all ports", t, func() {

		portSpec, _ := NewPortSpecFromString("1:65535", nil)
		ranges, err := GetUncoveredPortRanges(portSpec)

		Convey("Then result should match expected output", func() {
			expectedRanges := []*PortSpec{
				&PortSpec{Min: 1, Max: 65535},
			}

			So(ranges, ShouldResemble, expectedRanges)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I create pass nothing", t, func() {
		ranges, err := GetUncoveredPortRanges()

		Convey("Then result should match expected output", func() {
			expectedRanges := []*PortSpec{
				&PortSpec{Min: 1, Max: 65535},
			}

			So(ranges, ShouldResemble, expectedRanges)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I create pass empty portspec structure", t, func() {
		ranges, err := GetUncoveredPortRanges(&PortSpec{})

		Convey("Then result should match expected output", func() {
			expectedRanges := []*PortSpec{
				&PortSpec{Min: 1, Max: 65535},
			}

			So(ranges, ShouldResemble, expectedRanges)
			So(err, ShouldBeNil)
		})
	})
}
