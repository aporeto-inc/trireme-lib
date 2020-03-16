// +build !windows

package fqconfig

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestFqDefaultConfig(t *testing.T) {

	Convey("Given I create a new default filter queue config", t, func() {
		fqc := NewFilterQueueWithDefaults()
		Convey("Then I should see a config", func() {

			So(fqc, ShouldNotBeNil)

			So(fqc.GetMarkValue(), ShouldEqual, DefaultMarkValue)

			So(fqc.GetApplicationQueueSize(), ShouldEqual, DefaultQueueSize)
			So(fqc.GetNumApplicationQueues(), ShouldEqual, DefaultNumberOfQueues*4)
			So(fqc.GetApplicationQueueStart(), ShouldEqual, 0)
			So(fqc.GetApplicationQueueSynStr(), ShouldEqual, "0:3")
			So(fqc.GetApplicationQueueAckStr(), ShouldEqual, "4:7")
			So(fqc.GetApplicationQueueSynAckStr(), ShouldEqual, "8:11")
			So(fqc.GetApplicationQueueSvcStr(), ShouldEqual, "12:15")

			So(fqc.GetNetworkQueueSize(), ShouldEqual, DefaultQueueSize)
			So(fqc.GetNumNetworkQueues(), ShouldEqual, DefaultNumberOfQueues*4)
			So(fqc.GetNetworkQueueStart(), ShouldEqual, fqc.GetNumApplicationQueues())
			So(fqc.GetNetworkQueueSynStr(), ShouldEqual, "16:19")
			So(fqc.GetNetworkQueueAckStr(), ShouldEqual, "20:23")
			So(fqc.GetNetworkQueueSynAckStr(), ShouldEqual, "24:27")
			So(fqc.GetNetworkQueueSvcStr(), ShouldEqual, "28:31")
		})
	})
}
