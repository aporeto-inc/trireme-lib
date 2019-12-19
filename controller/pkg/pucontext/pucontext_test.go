package pucontext

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/policy"
)

func Test_NewPU(t *testing.T) {

	Convey("When I call NewPU with proper data", t, func() {

		fp := &policy.PUInfo{
			Runtime: policy.NewPURuntimeWithDefaults(),
			Policy:  policy.NewPUPolicyWithDefaults(),
		}

		pu, err := NewPU("pu1", fp, 24*time.Hour)

		Convey("I should not get error", func() {
			So(pu, ShouldNotBeNil)
			So(pu.HashID(), ShouldEqual, pu.hashID)
			So(err, ShouldBeNil)
		})
	})
}
