// +build linux

package connproc

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	sockOptOriginalDst = 80
)

type sockaddr struct {
	family uint16
	data   [14]byte
}

func getsockopt(s int, level int, name int, val uintptr, vallen *uint32) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

// GetOriginalDestination -- Func to get original destination a connection
func GetOriginalDestination(conn net.Conn) (net.IP, int, error) {
	var addr sockaddr
	size := uint32(unsafe.Sizeof(addr))

	inFile, err := conn.(*net.TCPConn).File()
	if err != nil {
		return []byte{}, 0, err
	}

	err = getsockopt(int(inFile.Fd()), syscall.SOL_IP, sockOptOriginalDst, uintptr(unsafe.Pointer(&addr)), &size)
	if err != nil {
		return []byte{}, 0, err
	}

	if addr.family != syscall.AF_INET {
		return []byte{}, 0, fmt.Errorf("invalid address family")
	}

	var ip net.IP
	ip = addr.data[2:6]
	port := int(addr.data[0])<<8 + int(addr.data[1])

	return ip, port, nil
}

func GetInterfaces() map[string]struct{} {
	ipmap := map[string]struct{}{}

	ifaces, _ := net.Interfaces()
	for _, intf := range ifaces {
		addrs, _ := intf.Addrs()
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip.To4() != nil {
				ipmap[ip.String()] = struct{}{}
			}
		}
	}
	return ipmap
}
