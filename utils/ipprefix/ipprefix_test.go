package ipprefix

import (
	"fmt"
	"net"
	"testing"

	"github.com/magiconair/properties/assert"
)

const (
	mask24  = "24mask"
	mask32  = "32mask"
	mask128 = "128mask"
	mask0   = "mask0"
)

func TestPutGetV4(t *testing.T) {
	ipcache := NewIPCache()

	ip := net.ParseIP("10.0.0.1")
	ipcache.Put(ip, 32, mask32)
	ipcache.Put(ip, 24, mask24)
	ipcache.Put(ip, 0, mask0)

	val, ok := ipcache.Get(ip, 32)
	assert.Equal(t, ok, true, "Get should return Success")
	assert.Equal(t, val.(string), mask32, fmt.Sprintf("Returned value should be %s", mask32))
	val, ok = ipcache.Get(net.ParseIP("10.0.0.2"), 24)
	assert.Equal(t, ok, true, "Get should return Success")
	assert.Equal(t, val.(string), mask24, fmt.Sprintf("Returned value should be %s", mask24))

	_, ok = ipcache.Get(net.ParseIP("8.8.8.8"), 0)
	assert.Equal(t, ok, true, "should be found in cache")

	_, ok = ipcache.Get(ip, 10)
	assert.Equal(t, ok, false, "Get should return nil")
}

func TestPutGetV6(t *testing.T) {
	ipcache := NewIPCache()

	ip := net.ParseIP("8000::220")
	ipcache.Put(ip, 128, mask128)
	ipcache.Put(ip, 24, mask24)
	ipcache.Put(ip, 0, mask0)

	val, ok := ipcache.Get(ip, 128)
	assert.Equal(t, ok, true, "Get should return success")
	assert.Equal(t, val.(string), mask128, fmt.Sprintf("Returned value should be %s", mask128))
	val, ok = ipcache.Get(ip, 24)
	assert.Equal(t, ok, true, "Get should return success")
	assert.Equal(t, val.(string), mask24, fmt.Sprintf("Returned value should be %s", mask24))

	_, ok = ipcache.Get(net.ParseIP("abcd::200"), 0)
	assert.Equal(t, ok, true, "Get should return success")

	_, ok = ipcache.Get(ip, 10)
	assert.Equal(t, ok, false, "Get should return nil")
}

func TestRunIPV4(t *testing.T) {
	var found bool

	ipcache := NewIPCache()

	ip := net.ParseIP("10.0.0.1")
	ipcache.Put(ip, 32, mask32)
	ipcache.Put(ip, 24, mask24)

	testRunIP := func(val interface{}) bool {
		found = false
		if val != nil {
			str := val.(string)

			if str == mask32 {
				found = true
			}
		}
		return true
	}

	ipcache.RunIP(ip, testRunIP)
	assert.Equal(t, found, true, "found should be true")
}

func TestRunIPv6(t *testing.T) {

	var found bool

	ipcache := NewIPCache()

	ip := net.ParseIP("8000::220")
	ipcache.Put(ip, 128, mask128)
	ipcache.Put(ip, 24, mask24)

	testRunIP := func(val interface{}) bool {
		found = false
		if val != nil {
			str := val.(string)

			if str == mask128 {
				found = true
			}
		}
		return true
	}

	ipcache.RunIP(ip, testRunIP)
	assert.Equal(t, found, true, "found should be true")
}

func TestRunValIPv4(t *testing.T) {

	ipcache := NewIPCache()

	ip := net.ParseIP("10.0.0.1")
	ipcache.Put(ip, 32, mask32)
	ipcache.Put(ip, 24, mask24)

	m := map[string]bool{}
	m[mask32] = true
	m[mask24] = true

	testRunVal := func(val interface{}) interface{} {
		if val != nil {
			s := val.(string)
			delete(m, s)
		}

		return val
	}

	ipcache.RunVal(testRunVal)
	assert.Equal(t, len(m), 0, "map should be of length 0")
}

func TestRunValIPv6(t *testing.T) {

	ipcache := NewIPCache()

	ip := net.ParseIP("8000::220")
	ipcache.Put(ip, 128, mask128)
	ipcache.Put(ip, 24, mask24)

	m := map[string]bool{}
	m[mask128] = true
	m[mask24] = true

	testRunVal := func(val interface{}) interface{} {
		if val != nil {
			s := val.(string)
			delete(m, s)
		}

		return val
	}

	ipcache.RunVal(testRunVal)
	assert.Equal(t, len(m), 0, "map should be of length 0")
}
