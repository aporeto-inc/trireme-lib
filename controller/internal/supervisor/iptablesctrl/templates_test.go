package iptablesctrl

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestChainName(t *testing.T) {
	Convey("When I test the creation of the name of the chain", t, func() {

		Convey("With a contextID of Context and version of 1", func() {
			app, net, err := chainName("Context", 1)
			So(err, ShouldBeNil)

			Convey("I should get the right names", func() {
				//app, net := i.chainName("Context", 1)

				So(app, ShouldContainSubstring, "TRI-App")
				So(net, ShouldContainSubstring, "TRI-Net")
			})
		})
	})
}
