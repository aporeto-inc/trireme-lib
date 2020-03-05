// +build windows

package extractors

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
)

func TestWindowsServiceEventMetadataExtractor(t *testing.T) {

	Convey("When I call the windows metadata extrator", t, func() {

		Convey("If all data are present", func() {
			event := &common.EventInfo{
				Name:       "./testdata/curl",
				Executable: "./testdata/curl",
				PID:        1234,
				PUID:       "/1234",
				Tags:       []string{"app=web"},
			}

			pu, err := WindowsServiceEventMetadataExtractor(event)
			Convey("I should get no error and a valid PU runitime", func() {
				So(err, ShouldBeNil)
				So(pu, ShouldNotBeNil)
			})
		})
	})
}
