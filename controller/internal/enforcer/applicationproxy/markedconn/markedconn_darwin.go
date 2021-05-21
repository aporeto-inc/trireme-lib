// +build darwin

package markedconn

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"go.aporeto.io/enforcerd/trireme-lib/utils/netinterfaces"
	"go.uber.org/zap"
)

// Control represents the dial control used to manipulate the raw connection.
type Control func(network, address string, c syscall.RawConn) error

// DialMarkedWithContext dials a TCP connection and associates a mark. Propagates the context.
func DialMarkedWithContext(ctx context.Context, network string, addr string, platformData *PlatformData, mark int) (net.Conn, error) {
	d := net.Dialer{}
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

// ControlFunc used in the dialer.
func ControlFunc(mark int, block bool, platformData *PlatformData) Control {
	return nil
}

// NewSocketListener creates a socket listener with marked connections.
func NewSocketListener(ctx context.Context, port string, mark int) (net.Listener, error) {
	listenerCfg := net.ListenConfig{}
	listener, err := listenerCfg.Listen(ctx, "tcp", port)

	if err != nil {
		return nil, fmt.Errorf("Failed to create listener: %s", err)
	}

	return ProxiedListener{netListener: listener, mark: mark}, nil
}

// ProxiedConnection is a proxied connection where we can recover the
// original destination.
type ProxiedConnection struct {
	net.Conn
	originalIP            net.IP
	originalPort          int
	originalTCPConnection *net.TCPConn
}

// PlatformData is proxy/socket data (platform-specific)
type PlatformData struct {
	handle          uintptr          // nolint: structcheck
	postConnectFunc func(fd uintptr) // nolint: structcheck
}

// GetTCPConnection returns the TCP connection object.
func (p *ProxiedConnection) GetTCPConnection() *net.TCPConn {
	return p.originalTCPConnection
}

// GetOriginalDestination sets the original destination of the connection.
func (p *ProxiedConnection) GetOriginalDestination() (net.IP, int) {
	return p.originalIP, p.originalPort
}

// GetPlatformData gets the socket data (needed for Windows)
func (p *ProxiedConnection) GetPlatformData() *PlatformData {
	return nil
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

	return &ProxiedConnection{nc, net.IP{}, 0, nil}, nil
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
	ipmap := map[string]struct{}{}

	ifaces, err := netinterfaces.GetInterfacesInfo()
	if err != nil {
		zap.L().Debug("Unable to get interfaces info", zap.Error(err))
	}

	for _, iface := range ifaces {
		for _, ip := range iface.IPs {
			ipmap[ip.String()] = struct{}{}
		}
	}

	return ipmap

}
