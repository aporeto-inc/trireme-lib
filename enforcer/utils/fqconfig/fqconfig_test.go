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
			So(fqc.GetNumApplicationQueues(), ShouldEqual, DefaultNumberOfQueues*3)
			So(fqc.GetApplicationQueueStart(), ShouldEqual, 0)
			So(fqc.GetApplicationQueueSynStr(), ShouldEqual, "0:3")
			So(fqc.GetApplicationQueueAckStr(), ShouldEqual, "4:7")
			So(fqc.GetApplicationQueueSvcStr(), ShouldEqual, "8:11")

			So(fqc.GetNetworkQueueSize(), ShouldEqual, DefaultQueueSize)
			So(fqc.GetNumNetworkQueues(), ShouldEqual, DefaultNumberOfQueues*3)
			So(fqc.GetNetworkQueueStart(), ShouldEqual, fqc.GetNumApplicationQueues())
			So(fqc.GetNetworkQueueSynStr(), ShouldEqual, "12:15")
			So(fqc.GetNetworkQueueAckStr(), ShouldEqual, "16:19")
			So(fqc.GetNetworkQueueSvcStr(), ShouldEqual, "20:23")
		})
	})
}
