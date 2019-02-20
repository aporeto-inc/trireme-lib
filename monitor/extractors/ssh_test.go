package extractors

import (
	"fmt"
	"strconv"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cgnetcls"
)

func testRuntime() *policy.PURuntime {

	tags := policy.NewTagStore()
	tags.AppendKeyValue("@sys:app", "web")
	tags.AppendKeyValue("@app:ssh:app", "web")
	tags.AppendKeyValue("$cert", "ss")

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}
	options := &policy.OptionsType{
		CgroupName: "/1234",
		CgroupMark: strconv.FormatUint(cgnetcls.MarkVal(), 10),
		UserID:     "/1234",
	}

	return policy.NewPURuntime("curl", 1234, "", tags, runtimeIps, common.SSHSessionPU, options)
}

func TestSSHMetadataExtractor(t *testing.T) {

	Convey("When I call the ssh metadata extrator", t, func() {

		Convey("If all data are present", func() {
			event := &common.EventInfo{
				Name: "curl",
				PID:  1234,
				PUID: "/1234",
				Tags: []string{"app=web", "$cert=ss"},
			}

			pu, err := SSHMetadataExtractor(event)
			Convey("I should get no error and a valid PU runtime", func() {
				So(err, ShouldBeNil)
				So(pu, ShouldNotBeNil)
				fmt.Println(pu.Options(), "=", testRuntime().Options())

				So(pu.Tags().String(), ShouldEqual, testRuntime().Tags().String())
			})
		})
	})
}
