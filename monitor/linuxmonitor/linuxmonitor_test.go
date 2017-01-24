package linuxmonitor

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
	. "github.com/smartystreets/goconvey/convey"
)

func TestSystemRPCMetadataExtractor(t *testing.T) {

}

func TestComputeMd5(t *testing.T) {
	Convey("When I calculate the MD5 of a bad file", t, func() {
		_, err := ComputeMd5("testdata/nofile")
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
		})
	})

	Convey("When I calculate the MD5 of a good file", t, func() {
		hash, err := ComputeMd5("testdata/curl")
		Convey("I should get no error and the right value", func() {
			So(err, ShouldBeNil)
			So(hex.EncodeToString(hash), ShouldResemble, "bf7e66d7bbd0465cfcba5b1cf68a9b59")
		})
	})

}

func TestFindFQDN(t *testing.T) {
	Convey("When I try to get the hostname of a good host", t, func() {
		hostname := findFQFN()

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

func TestSystemdRPCMetadataExtractor(t *testing.T) {
	Convey("When I call the metadata extrator", t, func() {
		Convey("If the event name is empty", func() {
			event := &rpcmonitor.EventInfo{}
			_, err := SystemdRPCMetadataExtractor(event)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If the PID is empty", func() {
			event := &rpcmonitor.EventInfo{
				Name: "process",
			}
			_, err := SystemdRPCMetadataExtractor(event)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If the PUID is empty", func() {
			event := &rpcmonitor.EventInfo{
				Name: "process",
				PID:  "1234",
			}
			_, err := SystemdRPCMetadataExtractor(event)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If all data are present", func() {
			event := &rpcmonitor.EventInfo{
				Name: "./testdata/curl",
				PID:  "1234",
				PUID: "/1234",
				Tags: map[string]string{
					"app": "web",
				},
			}

			pu, err := SystemdRPCMetadataExtractor(event)
			Convey("I should get no error and a valid PU runitime", func() {
				So(err, ShouldBeNil)
				So(pu, ShouldNotBeNil)
			})
		})

	})
}
