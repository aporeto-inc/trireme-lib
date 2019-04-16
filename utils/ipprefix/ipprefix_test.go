package ipprefix

import (
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestIPCache(t *testing.T) {
	Convey("Test the ip cache for long prefix match ipv4", t, func() {

		ipcache := NewIPCache()

		ip := net.ParseIP("10.0.0.1")
		str1 := "32mask"
		str2 := "24mask"
		ipcache.Put(ip, 32, str1)
		ipcache.Put(ip, 24, str2)

		val, ok := ipcache.Get(ip, 32)
		So(ok, ShouldEqual, true)
		So(val.(string), ShouldEqual, "32mask")
		val, ok = ipcache.Get(ip, 24)
		So(ok, ShouldEqual, true)
		So(val.(string), ShouldEqual, "24mask")

		_, ok = ipcache.Get(ip, 10)
		So(ok, ShouldEqual, false)

		var found bool
		testRunIP := func(val interface{}) bool {
			found = false
			if val != nil {
				str := val.(string)

				if str == "32mask" {
					found = true
				}
			}
			return true
		}

		ipcache.RunIP(ip, testRunIP)
		So(found, ShouldEqual, true)

		m := map[string]bool{}
		m[str1] = true
		m[str2] = true

		testRunVal := func(val interface{}) interface{} {
			if val != nil {
				s := val.(string)
				delete(m, s)
			}

			return val
		}

		ipcache.RunVal(testRunVal)
		So(len(m), ShouldEqual, 0)
	})

	Convey("Test the ip cache for long prefix match ipv6", t, func() {

		ipcache := NewIPCache()

		ip := net.ParseIP("8000::220")
		str1 := "128mask"
		str2 := "24mask"
		ipcache.Put(ip, 128, str1)
		ipcache.Put(ip, 24, str2)

		val, ok := ipcache.Get(ip, 128)
		So(ok, ShouldEqual, true)
		So(val.(string), ShouldEqual, str1)
		val, ok = ipcache.Get(ip, 24)
		So(ok, ShouldEqual, true)
		So(val.(string), ShouldEqual, str2)

		_, ok = ipcache.Get(ip, 10)
		So(ok, ShouldEqual, false)

		var found bool
		testFunc := func(val interface{}) bool {
			found = false
			if val != nil {
				str := val.(string)

				if str == str1 {
					found = true
				}
			}
			return true
		}

		ipcache.RunIP(ip, testFunc)
		So(found, ShouldEqual, true)
		m := map[string]bool{}
		m[str1] = true
		m[str2] = true

		testRunVal := func(val interface{}) interface{} {
			if val != nil {
				s := val.(string)
				delete(m, s)
			}

			return val
		}

		ipcache.RunVal(testRunVal)
		So(len(m), ShouldEqual, 0)
	})
}
