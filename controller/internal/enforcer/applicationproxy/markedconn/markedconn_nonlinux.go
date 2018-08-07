// +build darwin windows

package markedconn

import (
	"net"
)

// DialMarkedTCP creates a new TCP connection and marks it with the provided mark.
func DialMarkedTCP(network string, laddr, raddr *net.TCPAddr, mark int) (net.Conn, error) {

	return nil, nil
}

// MarkConnection is an OSX mock
func MarkConnection(conn net.Conn, mark int) error {
	return nil
}

// SocketListener creates a socket listener with SO_REUSEADDR.
func SocketListener(port string, mark int) (net.Listener, error) {
	return nil, nil
}

// ProxiedConnection is a proxied connection where we can recover the
// original destination.
type ProxiedConnection struct {
	net.Conn
	originalIP   net.IP
	originalPort int
}

// GetTCPConnection returns the TCP connection object.
func (p *ProxiedConnection) GetTCPConnection() *net.TCPConn {
	return nil
}

// GetOriginalDestination sets the original destination of the connection.
func (p *ProxiedConnection) GetOriginalDestination() (net.IP, int) {
	return p.originalIP, p.originalPort
}

// ProxiedListener is a proxied listener that uses proxied connections.
type ProxiedListener struct {
	netListener net.Listener
}

// Accept implements the accept method of the interface.
func (l ProxiedListener) Accept() (c net.Conn, err error) {
	nc, err := l.netListener.Accept()
	if err != nil {
		return nil, err
	}
	return &ProxiedConnection{nc, net.IP{}, 0}, nil
}

// Addr implements the Addr method of net.Listener.
func (l ProxiedListener) Addr() net.Addr {
	return l.netListener.Addr()
}

// Close implements the Close method of the net.Listener.
func (l ProxiedListener) Close() error {
	return l.netListener.Close()
}
