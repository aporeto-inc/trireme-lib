package extractors

import (
	"strconv"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/policy"
)

func testRuntime() *policy.PURuntime {

	tags := policy.NewTagStore()
	tags.AppendKeyValue("@app:ssh:app", "web")
	tags.AppendKeyValue("$cert", "ss")

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}
	options := &policy.OptionsType{
		CgroupName: "/1234",
		CgroupMark: strconv.FormatUint(103, 10),
	}

	return policy.NewPURuntime("curl", 1234, "", tags, runtimeIps, common.SSHSessionPU, options)
}

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
				So(pu, ShouldResemble, testRuntime())
			})
		})
	})
}
