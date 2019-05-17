// +build linux

package markedconn

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"go.aporeto.io/trireme-lib/utils/netinterfaces"
	"go.uber.org/zap"
)

const (
	sockOptOriginalDst = 80
)

// DialMarkedWithContext will dial a TCP connection to the provide address and mark the socket
// with the provided mark.
func DialMarkedWithContext(ctx context.Context, network string, addr string, mark int) (net.Conn, error) {
	d := net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {

				if err := syscall.SetNonblock(int(fd), false); err != nil {
					zap.L().Error("unable to set socket options", zap.Error(err))
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
					zap.L().Error("Failed to assing mark to socket", zap.Error(err))
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_TCP, 30, 1); err != nil {
					zap.L().Debug("Failed to set fast open socket option", zap.Error(err))
				}
			})
		},
	}

	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		zap.L().Error("Failed to dial to downstream node",
			zap.Error(err),
			zap.String("Address", addr),
			zap.String("Network type", network),
		)
	}
	return conn, err
}

// NewSocketListener will create a listener and mark the socket with the provided mark.
func NewSocketListener(ctx context.Context, port string, mark int) (net.Listener, error) {
	listenerCfg := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
					zap.L().Error("Failed to mark connection", zap.Error(err))
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_TCP, 23, 16*1024); err != nil {
					zap.L().Error("Cannot set tcp fast open options", zap.Error(err))
				}
			})
		},
	}

	listener, err := listenerCfg.Listen(ctx, "tcp4", port)
	if err != nil {
		return nil, fmt.Errorf("Failed to create listener: %s", err)
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

	tcpConn, ok := nc.(*net.TCPConn)
	if !ok {
		zap.L().Error("Received a non-TCP connection - this should never happen", zap.Error(err))
		return nil, fmt.Errorf("Not a tcp connection - ignoring")
	}

	ip, port, err := GetOriginalDestination(tcpConn)
	if err != nil {
		zap.L().Error("Failed to discover original destination - aborting", zap.Error(err))
		return nil, err
	}

	return &ProxiedConnection{
		originalIP:            ip,
		originalPort:          port,
		originalTCPConnection: tcpConn,
	}, nil
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
func GetOriginalDestination(conn *net.TCPConn) (net.IP, int, error) { // nolint interfacer

	var addr sockaddr
	size := uint32(unsafe.Sizeof(addr))

	rawconn, err := conn.SyscallConn()
	if err != nil {
		return nil, 0, err
	}

	if err := rawconn.Control(func(fd uintptr) {
		if err := getsockopt(int(fd), syscall.SOL_IP, sockOptOriginalDst, uintptr(unsafe.Pointer(&addr)), &size); err != nil {
			zap.L().Error("Failed to retrieve original destination", zap.Error(err))
		}
	}); err != nil {
		return nil, 0, fmt.Errorf("Failed to get original destination: %s", err)
	}

	if addr.family != syscall.AF_INET {
		return []byte{}, 0, fmt.Errorf("invalid address family")
	}

	ip := addr.data[2:6]
	port := int(addr.data[0])<<8 + int(addr.data[1])

	return ip, port, nil
}

func getsockopt(s int, level int, name int, val uintptr, vallen *uint32) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), val, uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

// GetInterfaces retrieves all the local interfaces.
func GetInterfaces() map[string]struct{} {
	ipmap := map[string]struct{}{}

	ifaces, err := netinterfaces.GetInterfacesInfo()
	if err != nil {
		zap.L().Debug("Unable to get interfaces info", zap.Error(err))
	}

	for _, iface := range ifaces {
		for _, ip := range iface.IPs {
			if ip.To4() != nil {
				ipmap[ip.String()] = struct{}{}
			}
		}
	}

	return ipmap
}
