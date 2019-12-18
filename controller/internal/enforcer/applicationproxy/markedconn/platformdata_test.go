// +build windows

package markedconn

import (
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestStoreTake(t *testing.T) {

	var nd *PlatformData

	Convey("Given a ProxiedListener with a PlatformDataControl", t, func() {

		proxiedListener := ProxiedListener{
			netListener:    nil,
			mark:           100,
			platformDataCtrl: NewPlatformDataControl(),
		}

		platformData := &PlatformData{
			1, func(fd uintptr) {},
		}

		ip := net.ParseIP("192.168.100.100")
		port := 20992

		Convey("When I store PlatformData for an ip/port, it should be retained until removed", func() {

			nd = TakePlatformData(proxiedListener, ip, port)
			So(nd, ShouldBeNil)

			proxiedListener.platformDataCtrl.StorePlatformData(ip, port, platformData)
			nd = TakePlatformData(proxiedListener, ip, port)
			So(nd, ShouldEqual, platformData)
			So(nd.handle, ShouldEqual, 1)

			nd = TakePlatformData(proxiedListener, ip, port)
			So(nd, ShouldBeNil)
		})
	})
}

func TestStoreRemove(t *testing.T) {

	var nd *PlatformData

	Convey("Given a ProxiedListener with a PlatformDataControl", t, func() {

		proxiedListener := ProxiedListener{
			netListener:    nil,
			mark:           101,
			platformDataCtrl: NewPlatformDataControl(),
		}

		platformData := &PlatformData{
			2, func(fd uintptr) {},
		}

		ip := net.ParseIP("192.168.100.101")
		port := 20993

		proxiedConn := &ProxiedConnection{
			originalIP:            ip,
			originalPort:          port,
			originalTCPConnection: nil,
			platformData:            platformData,
		}

		Convey("When I store PlatformData for an ip/port, it should be retained until removed", func() {

			nd = TakePlatformData(proxiedListener, ip, port)
			So(nd, ShouldBeNil)

			proxiedListener.platformDataCtrl.StorePlatformData(ip, port, platformData)
			nd = RemovePlatformData(proxiedListener, proxiedConn)
			So(nd, ShouldEqual, platformData)
			So(nd.handle, ShouldEqual, 2)

			nd = TakePlatformData(proxiedListener, ip, port)
			So(nd, ShouldBeNil)
		})
	})
}

func TestStoreMultiple(t *testing.T) {

	var nd *PlatformData

	Convey("Given a ProxiedListener with a PlatformDataControl", t, func() {

		proxiedListener := ProxiedListener{
			netListener:    nil,
			mark:           100,
			platformDataCtrl: NewPlatformDataControl(),
		}

		platformData1 := &PlatformData{
			1, func(fd uintptr) {},
		}
		platformData2 := &PlatformData{
			2, func(fd uintptr) {},
		}
		platformData3 := &PlatformData{
			3, func(fd uintptr) {},
		}

		ip1 := net.ParseIP("192.168.100.100")
		port1 := 20992

		ip2 := net.ParseIP("192.168.100.101")
		port2 := 20993

		Convey("When I store PlatformData for an ip/port, it should be retained until removed", func() {

			proxiedListener.platformDataCtrl.StorePlatformData(ip1, port1, platformData1)
			proxiedListener.platformDataCtrl.StorePlatformData(ip2, port2, platformData2)
			proxiedListener.platformDataCtrl.StorePlatformData(ip1, port1, platformData3)

			nd = TakePlatformData(proxiedListener, ip2, port2)
			So(nd, ShouldEqual, platformData2)
			So(nd.handle, ShouldEqual, 2)

			nd = TakePlatformData(proxiedListener, ip1, port1)
			So(nd, ShouldEqual, platformData3)
			So(nd.handle, ShouldEqual, 3)

			nd = TakePlatformData(proxiedListener, ip1, port1)
			So(nd, ShouldBeNil)
		})
	})
}
