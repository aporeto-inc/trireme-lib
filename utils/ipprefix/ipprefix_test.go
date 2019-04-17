package ipprefix

import (
	"fmt"
	"net"
	"testing"

	"github.com/magiconair/properties/assert"
)

func TestPutGetV4(t *testing.T) {
	ipcache := NewIPCache()

	ip := net.ParseIP("10.0.0.1")
	str1 := "32mask"
	str2 := "24mask"
	ipcache.Put(ip, 32, str1)
	ipcache.Put(ip, 24, str2)

	val, ok := ipcache.Get(ip, 32)
	assert.Equal(t, ok, true, "Get should return Success")
	assert.Equal(t, val.(string), str1, fmt.Sprintf("Returned value should be %s", str1))
	val, ok = ipcache.Get(net.ParseIP("10.0.0.2"), 24)
	assert.Equal(t, ok, true, "Get should return Success")
	assert.Equal(t, val.(string), str2, fmt.Sprintf("Returned value should be %s", str2))

	_, ok = ipcache.Get(ip, 10)
	assert.Equal(t, ok, false, "Get should return nil")
}

func TestPutGetV6(t *testing.T) {
	ipcache := NewIPCache()

	ip := net.ParseIP("8000::220")
	str1 := "128mask"
	str2 := "24mask"
	ipcache.Put(ip, 128, str1)
	ipcache.Put(ip, 24, str2)

	val, ok := ipcache.Get(ip, 128)
	assert.Equal(t, ok, true, "Get should return success")
	assert.Equal(t, val.(string), str1, fmt.Sprintf("Returned value should be %s", str1))
	val, ok = ipcache.Get(ip, 24)
	assert.Equal(t, ok, true, "Get should return success")
	assert.Equal(t, val.(string), str2, fmt.Sprintf("Returned value should be %s", str2))

	_, ok = ipcache.Get(ip, 10)
	assert.Equal(t, ok, false, "Get should return nil")
}

func TestRunIPV4(t *testing.T) {
	var found bool

	ipcache := NewIPCache()

	ip := net.ParseIP("10.0.0.1")
	str1 := "32mask"
	str2 := "24mask"
	ipcache.Put(ip, 32, str1)
	ipcache.Put(ip, 24, str2)

	testRunIP := func(val interface{}) bool {
		found = false
		if val != nil {
			str := val.(string)

			if str == str1 {
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
	str1 := "128mask"
	str2 := "24mask"
	ipcache.Put(ip, 128, str1)
	ipcache.Put(ip, 24, str2)

	testRunIP := func(val interface{}) bool {
		found = false
		if val != nil {
			str := val.(string)

			if str == str1 {
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
	str1 := "32mask"
	str2 := "24mask"
	ipcache.Put(ip, 32, str1)
	ipcache.Put(ip, 24, str2)

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
	assert.Equal(t, len(m), 0, "map should be of length 0")
}

func TestRunValIPv6(t *testing.T) {

	ipcache := NewIPCache()

	ip := net.ParseIP("8000::220")
	str1 := "128mask"
	str2 := "24mask"
	ipcache.Put(ip, 128, str1)
	ipcache.Put(ip, 24, str2)

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
	assert.Equal(t, len(m), 0, "map should be of length 0")
}
