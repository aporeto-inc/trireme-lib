package extractors

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
)

func TestUIDMetadataExtractor(t *testing.T) {

	Convey("When I call the uid metadata extrator", t, func() {
		Convey("If all data are present", func() {
			e := &common.EventInfo{
				PID:      100,
				Name:     "TestPU",
				Tags:     []string{"test=valid"},
				PUID:     "TestPU",
				Services: nil,
				PUType:   common.UIDLoginPU,
			}
			pu, err := UIDMetadataExtractor(e)
			So(err, ShouldBeNil)
			So(pu.Pid(), ShouldEqual, 100)
			So(pu.Name(), ShouldEqual, "TestPU")
		})
	})
}
