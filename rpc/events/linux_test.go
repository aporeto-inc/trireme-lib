// +build linux

package events

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/aporeto-inc/trireme-lib/policy"
	. "github.com/smartystreets/goconvey/convey"
)

func TestComputeFileMd5(t *testing.T) {

	Convey("When I calculate the MD5 of a bad file", t, func() {
		_, err := computeFileMd5("testdata/nofile")
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
		})
	})

	Convey("When I calculate the MD5 of a good file", t, func() {
		hash, err := computeFileMd5("testdata/curl")
		Convey("I should get no error and the right value", func() {
			So(err, ShouldBeNil)
			So(hex.EncodeToString(hash), ShouldResemble, "bf7e66d7bbd0465cfcba5b1cf68a9b59")
		})
	})
}

func TestFindFQDN(t *testing.T) {

	Convey("When I try to get the hostname of a good host", t, func() {
		hostname := findFQDN(1000 * time.Second)

		Convey("I should be able to resolve this hostname", func() {
			addr, err := net.LookupHost(hostname)
			So(err, ShouldBeNil)
			So(len(addr), ShouldBeGreaterThan, 0)
		})
	})
}

func TestLibs(t *testing.T) {

	Convey("When I try to get the libraries of a known binary", t, func() {
		libraries := libs("./testdata/curl")
		Convey("I should get the execpted libraries", func() {
			So(len(libraries), ShouldEqual, 4)
			So(libraries, ShouldContain, "libcurl-gnutls.so.4")
			So(libraries, ShouldContain, "libz.so.1")
			So(libraries, ShouldContain, "libpthread.so.0")
			So(libraries, ShouldContain, "libc.so.6")
		})
	})

	Convey("When I try to get the libraries of a bad binary", t, func() {

		libraries := libs("./testdata/nofile")
		Convey("I should get an empty array", func() {
			So(len(libraries), ShouldEqual, 0)
		})
	})
}

func TestSystemdEventMetadataExtractor(t *testing.T) {

	Convey("When I call the metadata extrator", t, func() {

		Convey("If all data are present", func() {
			event := &EventInfo{
				Name: "./testdata/curl",
				PID:  "1234",
				PUID: "/1234",
				Tags: []string{"app=web"},
			}

			pu, err := SystemdEventMetadataExtractor(event)
			Convey("I should get no error and a valid PU runitime", func() {
				So(err, ShouldBeNil)
				So(pu, ShouldNotBeNil)
			})
		})
	})
}

func TestDefaultHostMetadataExtractor(t *testing.T) {

	Convey("When I call the host metadata extractor", t, func() {

		Convey("If its valid data", func() {

			services := []policy.Service{
				policy.Service{
					Protocol: uint8(6),
					Port:     uint16(1000),
				},
			}

			event := &EventInfo{
				Name:     "Web",
				PID:      "1234",
				PUID:     "Web",
				Tags:     []string{"app=web"},
				Services: services,
			}

			pu, err := DefaultHostMetadataExtractor(event)
			Convey("I should get no error and a valid PU runtimg", func() {
				So(err, ShouldBeNil)
				So(pu, ShouldNotBeNil)
				So(pu.Options().CgroupName, ShouldResemble, "Web")
				So(pu.Options().Services, ShouldResemble, services)
			})
		})

		Convey("If I get invalid tags", func() {

			event := &EventInfo{
				Name: "Web",
				PID:  "1234",
				PUID: "Web",
				Tags: []string{"invalid"},
			}

			_, err := DefaultHostMetadataExtractor(event)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If I get an invalid PID", func() {

			event := &EventInfo{
				Name: "Web",
				PID:  "zxczxc",
				PUID: "Web",
				Tags: []string{"invalid"},
			}

			_, err := DefaultHostMetadataExtractor(event)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}
