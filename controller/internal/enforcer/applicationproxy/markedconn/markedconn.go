// +build linux

package markedconn

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/rs/xid"
)

const (
	sockOptOriginalDst = 80
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

	if err := setSocketTimeout(fd, time.Second*5); err != nil {
		return nil, fmt.Errorf("Failed to set connect timeout: %s", err)
	}

	if err := syscall.Connect(fd, address); err != nil {
		conn.Close() // nolint
		return nil, fmt.Errorf("Unable to connect: %s", err)
	}

	// if err := setSocketTimeout(fd, 0); err != nil {
	// 	return nil, fmt.Errorf("Failed to set connect timeout: %s", err)
	// }

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
	originalIP            net.IP
	originalPort          int
	originalTCPConnection *net.TCPConn
}

// GetOriginalDestination sets the original destination of the connection.
func (p *ProxiedConnection) GetOriginalDestination() (net.IP, int) {
	return p.originalIP, p.originalPort
}

// GetTCPConnection returns the TCP connection object.
func (p *ProxiedConnection) GetTCPConnection() *net.TCPConn {
	return p.originalTCPConnection
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

// RemoteAddr returns the remote address
func (p *ProxiedConnection) RemoteAddr() net.Addr {
	return p.originalTCPConnection.RemoteAddr()
}

// Read reads data from the connection.
func (p *ProxiedConnection) Read(b []byte) (n int, err error) {
	return p.originalTCPConnection.Read(b)
}

// Write writes data to the connection.
func (p *ProxiedConnection) Write(b []byte) (n int, err error) {
	return p.originalTCPConnection.Write(b)
}

// Close closes the connection.
func (p *ProxiedConnection) Close() error {
	return p.originalTCPConnection.Close()
}

// SetDeadline passes the read deadline to the original TCP connection.
func (p *ProxiedConnection) SetDeadline(t time.Time) error {
	return p.originalTCPConnection.SetDeadline(t)
}

// SetReadDeadline implements the call by passing it to the original connection.
func (p *ProxiedConnection) SetReadDeadline(t time.Time) error {
	return p.originalTCPConnection.SetReadDeadline(t)
}

// SetWriteDeadline implements the call by passing it to the original connection.
func (p *ProxiedConnection) SetWriteDeadline(t time.Time) error {
	return p.originalTCPConnection.SetWriteDeadline(t)
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
		return nil, err
	}

	if err = MarkConnection(nc, l.mark); err != nil {
		return nil, err
	}

	newConnection, ip, port, err := GetOriginalDestination(nc)
	if err != nil {
		return nil, err
	}

	tcpConn, ok := newConnection.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("Not a tcp connection - ignoring")
	}

	return &ProxiedConnection{ip, port, tcpConn}, nil
}

// Addr implements the Addr method of net.Listener.
func (l ProxiedListener) Addr() net.Addr {
	return l.netListener.Addr()
}

// Close implements the Close method of the net.Listener.
func (l ProxiedListener) Close() error {
	return l.netListener.Close()
}

type sockaddr struct {
	family uint16
	data   [14]byte
}

// GetOriginalDestination -- Func to get original destination a connection
func GetOriginalDestination(conn net.Conn) (net.Conn, net.IP, int, error) { // nolint interfacer
	var addr sockaddr
	size := uint32(unsafe.Sizeof(addr))

	inFile, err := conn.(*net.TCPConn).File()
	if err != nil {
		return nil, []byte{}, 0, err
	}
	defer inFile.Close() // nolint errcheck

	// This places the connection in blocking mode and the deadlines stop
	// working. After we find the original destination we need a big
	// hacky work-around to create a new connection out of the fd.
	// TODO: It is fixed with Go 1.11. Will be removed in the future
	err = getsockopt(int(inFile.Fd()), syscall.SOL_IP, sockOptOriginalDst, uintptr(unsafe.Pointer(&addr)), &size)
	if err != nil {
		return nil, []byte{}, 0, err
	}

	if addr.family != syscall.AF_INET {
		return nil, []byte{}, 0, fmt.Errorf("invalid address family")
	}

	var ip net.IP
	ip = addr.data[2:6]
	port := int(addr.data[0])<<8 + int(addr.data[1])

	// Here we create a new connection object and return that one to avoid
	// the blocking issue.
	// TODO: Remove with Go 1.11
	newConn, err := net.FileConn(inFile)
	if err != nil {
		return nil, []byte{}, 0, fmt.Errorf("Unable to start new connection")
	}
	conn.Close() // nolint errcheck
	return newConn, ip, port, nil
}

func getsockopt(s int, level int, name int, val uintptr, vallen *uint32) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

// setSocketTimeout sets the receive and send timeouts on the given socket.
func setSocketTimeout(fd int, timeout time.Duration) error {
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	for _, opt := range []int{syscall.SO_RCVTIMEO, syscall.SO_SNDTIMEO} {
		if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, opt, &tv); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	}
	return nil
}
