// +build windows

package markedconn

import (
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestStoreTake(t *testing.T) {

	var nd *NativeData

	Convey("Given a ProxiedListener with a NativeDataControl", t, func() {

		proxiedListener := ProxiedListener{
			netListener:    nil,
			mark:           100,
			nativeDataCtrl: NewNativeDataControl(),
		}

		nativeData := &NativeData{
			1, func(fd uintptr) {},
		}

		ip := net.ParseIP("192.168.100.100")
		port := 20992

		Convey("When I store NativeData for an ip/port, it should be retained until removed", func() {

			nd = TakeNativeData(proxiedListener, ip, port)
			So(nd, ShouldBeNil)

			proxiedListener.nativeDataCtrl.StoreNativeData(ip, port, nativeData)
			nd = TakeNativeData(proxiedListener, ip, port)
			So(nd, ShouldEqual, nativeData)
			So(nd.handle, ShouldEqual, 1)

			nd = TakeNativeData(proxiedListener, ip, port)
			So(nd, ShouldBeNil)
		})
	})
}

func TestStoreRemove(t *testing.T) {

	var nd *NativeData

	Convey("Given a ProxiedListener with a NativeDataControl", t, func() {

		proxiedListener := ProxiedListener{
			netListener:    nil,
			mark:           101,
			nativeDataCtrl: NewNativeDataControl(),
		}

		nativeData := &NativeData{
			2, func(fd uintptr) {},
		}

		ip := net.ParseIP("192.168.100.101")
		port := 20993

		proxiedConn := &ProxiedConnection{
			originalIP:            ip,
			originalPort:          port,
			originalTCPConnection: nil,
			nativeData:            nativeData,
		}

		Convey("When I store NativeData for an ip/port, it should be retained until removed", func() {

			nd = TakeNativeData(proxiedListener, ip, port)
			So(nd, ShouldBeNil)

			proxiedListener.nativeDataCtrl.StoreNativeData(ip, port, nativeData)
			nd = RemoveNativeData(proxiedListener, proxiedConn)
			So(nd, ShouldEqual, nativeData)
			So(nd.handle, ShouldEqual, 2)

			nd = TakeNativeData(proxiedListener, ip, port)
			So(nd, ShouldBeNil)
		})
	})
}

func TestStoreMultiple(t *testing.T) {

	var nd *NativeData

	Convey("Given a ProxiedListener with a NativeDataControl", t, func() {

		proxiedListener := ProxiedListener{
			netListener:    nil,
			mark:           100,
			nativeDataCtrl: NewNativeDataControl(),
		}

		nativeData1 := &NativeData{
			1, func(fd uintptr) {},
		}
		nativeData2 := &NativeData{
			2, func(fd uintptr) {},
		}
		nativeData3 := &NativeData{
			3, func(fd uintptr) {},
		}

		ip1 := net.ParseIP("192.168.100.100")
		port1 := 20992

		ip2 := net.ParseIP("192.168.100.101")
		port2 := 20993

		Convey("When I store NativeData for an ip/port, it should be retained until removed", func() {

			proxiedListener.nativeDataCtrl.StoreNativeData(ip1, port1, nativeData1)
			proxiedListener.nativeDataCtrl.StoreNativeData(ip2, port2, nativeData2)
			proxiedListener.nativeDataCtrl.StoreNativeData(ip1, port1, nativeData3)

			nd = TakeNativeData(proxiedListener, ip2, port2)
			So(nd, ShouldEqual, nativeData2)
			So(nd.handle, ShouldEqual, 2)

			nd = TakeNativeData(proxiedListener, ip1, port1)
			So(nd, ShouldEqual, nativeData3)
			So(nd.handle, ShouldEqual, 3)

			nd = TakeNativeData(proxiedListener, ip1, port1)
			So(nd, ShouldBeNil)
		})
	})
}
