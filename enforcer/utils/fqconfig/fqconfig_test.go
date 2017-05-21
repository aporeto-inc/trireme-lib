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
		})
	})
}
