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
			So(fqc.NetworkSynQueues, ShouldResemble, []uint32{16, 17, 18, 19})
			So(fqc.NetworkSynAckQueues, ShouldResemble, []uint32{24, 25, 26, 27})
			So(fqc.NetworkAckQueues, ShouldResemble, []uint32{20, 21, 22, 23})
			So(fqc.ApplicationSynQueues, ShouldResemble, []uint32{0, 1, 2, 3})
			So(fqc.ApplicationAckQueues, ShouldResemble, []uint32{4, 5, 6, 7})
			So(fqc.ApplicationSynAckQueues, ShouldResemble, []uint32{8, 9, 10, 11})
		})
	})
}
