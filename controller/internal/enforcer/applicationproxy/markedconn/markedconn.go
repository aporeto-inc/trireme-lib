// +build linux

package markedconn

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"

	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/connproc"
	"github.com/rs/xid"
)

// DialMarkedTCP creates a new TCP connection and marks it with the provided mark.
func DialMarkedTCP(network string, laddr, raddr *net.TCPAddr, mark int) (net.Conn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("Failed to create socket: %s", err)
	}

	f := os.NewFile(uintptr(fd), xid.New().String())
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

	if err := syscall.Connect(fd, address); err != nil {
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

// SocketListener creates a TCP listener through system calls giving us more
// control over the specific parameters that we need.
func SocketListener(port string, mark int) (net.Listener, error) {

	addr, err := net.ResolveTCPAddr("tcp4", port)
	if err != nil {
		return nil, fmt.Errorf("Cannot resolve v4 IP: %s", err)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}

	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, fmt.Errorf("cannot set SO_REUSEADDR: %s", err)
	}

	if len(addr.IP) == 0 {
		addr.IP = net.IPv4zero
	}
	socketAddress := &syscall.SockaddrInet4{Port: addr.Port}
	copy(socketAddress.Addr[:], addr.IP.To4())

	if err = syscall.Bind(fd, socketAddress); err != nil {
		syscall.Close(fd) // nolint errcheck
		return nil, err
	}

	if err = syscall.Listen(fd, 256); err != nil {
		syscall.Close(fd) // nolint errcheck
		return nil, err
	}

	f := os.NewFile(uintptr(fd), addr.String())
	defer f.Close() // nolint errcheck

	listener, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("Cannot bind listener: %s", err)
	}

	return ProxiedListener{netListener: listener, mark: mark}, nil
}

// ProxiedConnection is a proxied connection where we can recover the
// original destination.
type ProxiedConnection struct {
	net.Conn
	originalIP   net.IP
	originalPort int
}

// GetOriginalDestination sets the original destination of the connection.
func (p *ProxiedConnection) GetOriginalDestination() (net.IP, int) {
	return p.originalIP, p.originalPort
}

// LocalAddr implements the corresponding method of net.Conn, but returns the original
// address.
func (p *ProxiedConnection) LocalAddr() net.Addr {

	addr, err := net.ResolveTCPAddr("tcp", p.originalIP.String()+":"+strconv.Itoa(p.originalPort))
	if err != nil {
		return nil
	}

	return addr
}

// ProxiedListener is a proxied listener that uses proxied connections.
type ProxiedListener struct {
	netListener net.Listener
	mark        int
}

// Accept implements the accept method of the interface.
func (l ProxiedListener) Accept() (c net.Conn, err error) {
	nc, err := l.netListener.Accept()
	if err != nil {
		fmt.Println("I got an error", err)
		return nil, err
	}

	ip, port, err := connproc.GetOriginalDestination(nc)
	if err != nil {
		return nil, err
	}

	if err := MarkConnection(nc, l.mark); err != nil {
		return nil, err
	}

	return &ProxiedConnection{nc, ip, port}, nil
}

// Addr implements the Addr method of net.Listener.
func (l ProxiedListener) Addr() net.Addr {
	return l.netListener.Addr()
}

// Close implements the Close method of the net.Listener.
func (l ProxiedListener) Close() error {
	return l.netListener.Close()
}
