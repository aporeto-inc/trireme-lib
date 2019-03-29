package podmonitor

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestConfig(t *testing.T) {
	Convey("SetupDefaultConfig should just return the config as is", t, func() {
		c := SetupDefaultConfig(&Config{
			Kubeconfig:        "test",
			Nodename:          "test",
			EnableHostPods:    true,
			MetadataExtractor: nil,
			NetclsProgrammer:  nil,
		})
		So(c.Kubeconfig, ShouldEqual, "test")
		So(c.Nodename, ShouldEqual, "test")
		So(c.EnableHostPods, ShouldBeTrue)
		So(c.MetadataExtractor, ShouldBeNil)
		So(c.NetclsProgrammer, ShouldBeNil)
	})

	Convey("DefaultConfig should always return a pointer to a config", t, func() {
		c := DefaultConfig()
		So(c, ShouldNotBeNil)
	})
}
