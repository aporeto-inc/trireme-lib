package extractors

import (
	"strconv"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/policy"
)

func createDummyPolicy(event *common.EventInfo) *policy.PURuntime {
	runtimeTags := policy.NewTagStore()
	runtimeTags.AppendKeyValue("@sys:test", "valid")
	runtimeTags.AppendKeyValue("@app:linux:test", "valid")
	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}
	options := &policy.OptionsType{
		CgroupName: event.PUID,
		CgroupMark: strconv.Itoa(105),
		UserID:     event.PUID,
		Services:   nil,
	}
	return policy.NewPURuntime(event.Name, int(event.PID), "", runtimeTags, runtimeIps, common.UIDLoginPU, options)
}
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
