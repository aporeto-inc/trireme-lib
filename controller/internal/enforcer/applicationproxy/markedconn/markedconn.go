// +build linux

package markedconn

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// DialMarkedTCP creates a new TCP connection and marks it with the provided mark.
func DialMarkedTCP(network string, laddr, raddr *net.TCPAddr, mark int) (net.Conn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("Failed to create socket: %s", err)
	}

	f := os.NewFile(uintptr(fd), raddr.String())
	defer f.Close() // nolint

	conn, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("Unable to create downstream connection: %s", err)
	}

	address := &syscall.SockaddrInet4{
		Port: raddr.Port,
	}
	copy(address.Addr[:], raddr.IP.To4())

	if err = syscall.SetNonblock(fd, false); err != nil {
		conn.Close() // nolint
		return nil, fmt.Errorf("unable to set socket options: %s", err)
	}

	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark)
	if err != nil {
		conn.Close() // nolint
		return nil, fmt.Errorf("Failed to assing mark to socket: %s", err)
	}

	if err = syscall.Connect(fd, address); err != nil {
		conn.Close() // nolint
		return nil, fmt.Errorf("Unable to connect: %s", err)
	}

	return conn, nil
}

// MarkConnection marks an existing connection with a mark
func MarkConnection(conn net.Conn, mark int) error {
	setMark := func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark) // nolint
	}

	rawconn, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		return err
	}

	return rawconn.Control(setMark)
}
