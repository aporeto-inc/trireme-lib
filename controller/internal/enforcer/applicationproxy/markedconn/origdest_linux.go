// +build linux

package markedconn

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	sockOptOriginalDst = 80
)

type sockaddr4 struct {
	family uint16
	data   [14]byte
}

type sockaddr6 struct {
	family   uint16
	port     [2]byte
	flowInfo [4]byte //nolint
	ip       [16]byte
	scopeID  [4]byte //nolint
}

type origDest func(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

func getOriginalDestPlatform(rawConn passFD, v4Proto bool) (net.IP, int, *NativeData, error) {
	return getOriginalDestInternal(rawConn, v4Proto, syscall.Syscall6)
}

func getOriginalDestInternal(rawConn passFD, v4Proto bool, getOrigDest origDest) (net.IP, int, *NativeData, error) { // nolint interfacer{
	var getsockopt func(fd uintptr)
	var netIP net.IP
	var port int
	var err error

	getsockopt4 := func(fd uintptr) {
		var addr sockaddr4
		size := uint32(unsafe.Sizeof(addr))
		_, _, e1 := getOrigDest(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(syscall.SOL_IP), uintptr(sockOptOriginalDst), uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)), 0) //nolint

		if e1 != 0 {
			err = fmt.Errorf("Failed to get original destination: %s", e1)
			return
		}

		if addr.family != syscall.AF_INET {
			err = fmt.Errorf("invalid address family. Expected AF_INET")
			return
		}

		netIP = addr.data[2:6]
		port = int(addr.data[0])<<8 + int(addr.data[1])
	}

	getsockopt6 := func(fd uintptr) {
		var addr sockaddr6
		size := uint32(unsafe.Sizeof(addr))

		_, _, e1 := getOrigDest(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(syscall.SOL_IPV6), uintptr(sockOptOriginalDst), uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)), 0) //nolint
		if e1 != 0 {
			err = fmt.Errorf("Failed to get original destination: %s", e1)
			return
		}

		if addr.family != syscall.AF_INET6 {
			err = fmt.Errorf("invalid address family. Expected AF_INET6")
			return
		}

		netIP = addr.ip[:]
		port = int(addr.port[0])<<8 + int(addr.port[1])
	}

	if v4Proto {
		getsockopt = getsockopt4
	} else {
		getsockopt = getsockopt6
	}

	if err1 := rawConn.Control(getsockopt); err1 != nil {
		return nil, 0, nil, fmt.Errorf("Failed to get original destination: %s", err)
	}

	if err != nil {
		return nil, 0, nil, err
	}

	return netIP, port, nil, nil
}
