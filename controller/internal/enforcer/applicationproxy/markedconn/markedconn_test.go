// +build linux

package markedconn

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"
	"testing"
	"unsafe"

	"github.com/magiconair/properties/assert"
)

type testPassFD struct {
}

func (*testPassFD) Control(f func(uintptr)) error {
	f(0)
	return nil
}

func TestGetOrigDestV4(t *testing.T) {

	testGetOrigV4 := func(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {

		assert.Equal(t, trap, uintptr(syscall.SYS_GETSOCKOPT), "expected syscall trap to be SYS.GETSOCKOPT")
		assert.Equal(t, unsafe.Alignof(a4), unsafe.Alignof(&sockaddr4{}), "uintptr and sockaddr4 alignment must be the same")
		sa := (*(*sockaddr4)(unsafe.Pointer(a4))) //nolint
		sa.family = syscall.AF_INET

		copy(sa.data[2:6], []byte{127, 0, 0, 1})
		binary.BigEndian.PutUint16(sa.data[:2], 3000)

		*(*sockaddr4)(unsafe.Pointer(a4)) = sa // nolint
		return 0, 0, 0
	}

	test := &testPassFD{}
	ip, port, _, _ := getOriginalDestInternal(test, true, testGetOrigV4)
	assert.Equal(t, ip.String(), "127.0.0.1", "ip should be 127.0.0.1")
	assert.Equal(t, port, 3000, "port should be 3000")
}

func TestGetOrigDestV6(t *testing.T) {
	testGetOrigV6 := func(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
		assert.Equal(t, trap, uintptr(syscall.SYS_GETSOCKOPT), "expected syscall trap to be SYS.GETSOCKOPT")
		assert.Equal(t, unsafe.Alignof(a4), unsafe.Alignof(&sockaddr6{}), "uintptr and sockaddr6 alignment must be the same")
		sa := (*(*sockaddr6)(unsafe.Pointer(a4))) //nolint
		sa.family = syscall.AF_INET6

		copy(sa.ip[:], net.ParseIP("::1"))
		binary.BigEndian.PutUint16(sa.port[:], 3000)

		*(*sockaddr6)(unsafe.Pointer(a4)) = sa //nolint
		return 0, 0, 0
	}

	test := &testPassFD{}
	ip, port, _, _ := getOriginalDestInternal(test, false, testGetOrigV6) //nolint
	assert.Equal(t, ip.String(), "::1", "ip should be ::1")
	assert.Equal(t, port, 3000, "port should be 3000")
}

func TestGetOrigDestV4Err1(t *testing.T) {

	testGetOrigV4 := func(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
		return 0, 0, 0
	}

	test := &testPassFD{}
	_, _, _, err := getOriginalDestInternal(test, true, testGetOrigV4) //nolint

	assert.Equal(t, err != nil, true, "error should not be nil")
}

func TestGetOrigDestV6Err1(t *testing.T) {
	testGetOrigV6 := func(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
		return 0, 0, 0
	}

	test := &testPassFD{}
	_, _, _, err := getOriginalDestInternal(test, false, testGetOrigV6) //nolint
	assert.Equal(t, err != nil, true, "error should not be nil")
}

func TestGetOrigDestV4Err2(t *testing.T) {

	testGetOrigV4 := func(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
		return 0, 0, 1
	}

	test := &testPassFD{}
	_, _, _, err := getOriginalDestInternal(test, true, testGetOrigV4) //nolint
	assert.Equal(t, err != nil, true, "error should not be nil")
}

func TestGetOrigDestV6Err2(t *testing.T) {
	testGetOrigV6 := func(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
		return 0, 0, 1
	}

	test := &testPassFD{}

	_, _, _, err := getOriginalDestInternal(test, false, testGetOrigV6) //nolint
	assert.Equal(t, err != nil, true, "error should not be nil")
}

func TestLocalAddr(t *testing.T) {
	ip, _, _ := net.ParseCIDR("172.17.0.2/24")
	proxyConn := ProxiedConnection{originalIP: ip, originalPort: 80}

	naddr := proxyConn.LocalAddr()
	netAddr := naddr.(*net.TCPAddr)

	assert.Equal(t, ip, netAddr.IP, "ip should be equal to 172.17.0.2")
	assert.Equal(t, 80, netAddr.Port, "ip should be equal to 172.17.0.2")
}

func TestSocketListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background()) //nolint
	_, err := NewSocketListener(ctx, ":1111", 100)

	assert.Equal(t, err, nil, "error  should be nil")
	cancel() //nolint
}

func TestGetInterfaces(t *testing.T) {

	ipmap := GetInterfaces()

	b := len(ipmap) != 0
	assert.Equal(t, b, true, "ipmap should not be empty")
}
