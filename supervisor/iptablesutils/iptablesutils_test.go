package iptablesutils

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/aporeto-inc/mock/gomock"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/provider/mock"
	. "github.com/smartystreets/goconvey/convey"
)

func TestAppChainPrefix(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIpt := mockprovider.NewMockIptablesProvider(ctrl)

	Convey("Given I create an iptables utility", t, func() {

		ipu := NewIptableUtils(mockIpt)

		Convey("When I call AppChainPrefix", func() {

			context := "somecontext"
			index := 345
			prefix := ipu.AppChainPrefix(context, index)

			Convey("Then I should get an AppChainPrefix", func() {

				So(prefix, ShouldEqual, "TRIREME-App-"+context+"-"+strconv.Itoa(index))
			})
		})
	})
}

func TestNetChainPrefix(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIpt := mockprovider.NewMockIptablesProvider(ctrl)

	Convey("Given I create an iptables utility", t, func() {

		ipu := NewIptableUtils(mockIpt)

		Convey("When I call NetChainPrefix", func() {

			context := "somecontext"
			index := 12321312
			prefix := ipu.NetChainPrefix(context, index)

			Convey("Then I should get an NetChainPrefix", func() {

				So(prefix, ShouldEqual, "TRIREME-Net-"+context+"-"+strconv.Itoa(index))
			})
		})
	})
}

func TestDefaultCacheIP(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIpt := mockprovider.NewMockIptablesProvider(ctrl)

	Convey("Given I create an iptables utility", t, func() {

		ipu := NewIptableUtils(mockIpt)

		Convey("When I call DefaultCacheIP with empty ip list", func() {

			ip, err := ipu.DefaultCacheIP(nil)

			Convey("Then I should get 0.0.0.0/", func() {

				So(ip, ShouldResemble, "0.0.0.0/0")
				So(err, ShouldBeNil)
			})
		})

		Convey("When I call DefaultCacheIP with ip list", func() {

			ips := policy.NewIPMap(map[string]string{
				policy.DefaultNamespace: "172.0.0.1",
				"otherspace":            "10.10.10.10",
			})
			ip, err := ipu.DefaultCacheIP(ips)

			Convey("Then I should get the first ip", func() {

				So(ip, ShouldEqual, ips.IPs[policy.DefaultNamespace])
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestFilterMarkedPacketsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIpt := mockprovider.NewMockIptablesProvider(ctrl)

	Convey("Given I create an iptables utility", t, func() {

		ipu := NewIptableUtils(mockIpt)

		Convey("When I call FilterMarkedPackets to induce an error", func() {

			mark := 10
			mockIpt.EXPECT().Insert(appAckPacketIPTableContext, appPacketIPTableSection, 1,
				"-m", "mark",
				"--mark", strconv.Itoa(mark),
				"-j", "ACCEPT").Return(fmt.Errorf("Some Error"))

			err := ipu.FilterMarkedPackets(mark)

			Convey("Then I should get and error", func() {

				So(err, ShouldNotBeNil)
			})
		})
	})
}
