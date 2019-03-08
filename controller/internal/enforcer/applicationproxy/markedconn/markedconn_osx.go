// +build darwin

package markedconn

import (
	"context"
	"net"
)

// DialMarkedWithContext dials a TCP connection and associates a mark. Propagates the context.
func DialMarkedWithContext(ctx context.Context, network string, addr string, mark int) (net.Conn, error) {
	return nil, nil
}

// NewSocketListener creates a socket listener with marked connections.
func NewSocketListener(ctx context.Context, port string, mark int) (net.Listener, error) {
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

// GetInterfaces retrieves all the local interfaces.
func GetInterfaces() map[string]struct{} {
	return nil
}
