package extractors

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
)

func TestSSHMetadataExtractor(t *testing.T) {

	Convey("When I call the ssh metadata extrator", t, func() {

		Convey("If all data are present", func() {
			event := &common.EventInfo{
				Name:   "curl",
				PID:    1234,
				PUID:   "/1234",
				PUType: common.SSHSessionPU,
				Tags:   []string{"app=web", "$cert=ss"},
			}

			pu, err := SSHMetadataExtractor(event)
			Convey("I should get no error and a valid PU runtime", func() {
				So(err, ShouldBeNil)
				So(pu.Pid(), ShouldEqual, 1234)
				So(pu.Name(), ShouldEqual, "curl")
				So(pu.Tags().Tags, ShouldResemble, []string{"@user:ssh:app=web", "$cert=ss"})
			})
		})
	})
}
