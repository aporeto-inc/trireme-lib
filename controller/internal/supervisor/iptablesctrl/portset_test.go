package iptablesctrl

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/policy"
)

func testCreatePortSet(portset string) error {
	return nil
}

func TestPortSet(t *testing.T) {
	Convey("When I create a new iptables instance", t, func() {
		i, err := createTestInstance(constants.LocalServer)
		Convey("It should succeed", func() {
			So(i, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(i.appPacketIPTableSection, ShouldResemble, "OUTPUT")
			So(i.netPacketIPTableSection, ShouldResemble, "INPUT")
		})

		i.createPUPortSet = testCreatePortSet
		puInfo := policy.NewPUInfo("SomeProcessingUnitId", common.LinuxProcessPU)
		err = i.createPortSet("1001", puInfo)
		So(err, ShouldBeNil)
		err = i.AddPortToPortSet("1001", "80")
		So(err.Error(), ShouldContainSubstring, "unable to add")
		err = i.DeletePortFromPortSet("1001", "80")
		So(err.Error(), ShouldContainSubstring, "unable to delete")
		err = i.deletePortSet("1001")
		So(err.Error(), ShouldContainSubstring, "Failed to delete")
	})
}
