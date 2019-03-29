package extractors

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestErrors(t *testing.T) {
	Convey("Testing ErrNetclsAlreadyProgrammed handling functions", t, func() {
		err := ErrNetclsAlreadyProgrammed("mark")
		So(err, ShouldNotBeNil)

		expected := fmt.Sprintf("net_cls cgroup already programmed with mark %s", "mark")
		So(err.Error(), ShouldEqual, expected)

		So(IsErrNetclsAlreadyProgrammed(err), ShouldBeTrue)
		So(IsErrNetclsAlreadyProgrammed(ErrNoHostNetworkPod), ShouldBeFalse)
	})
	Convey("Testing ErrNoHostNetworkPod handling functions", t, func() {
		So(IsErrNoHostNetworkPod(ErrNoHostNetworkPod), ShouldBeTrue)
		So(IsErrNoHostNetworkPod(fmt.Errorf("random")), ShouldBeFalse)
	})
}
