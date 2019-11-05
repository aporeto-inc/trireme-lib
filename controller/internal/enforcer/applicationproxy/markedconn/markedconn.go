// +build linux windows

package markedconn

import (
	"context"
	"fmt"
	"net"
	"time"

	"go.aporeto.io/trireme-lib/utils/netinterfaces"
	"go.uber.org/zap"
)

// DialMarkedWithContext will dial a TCP connection to the provide address and mark the socket
// with the provided mark.
func DialMarkedWithContext(ctx context.Context, network string, addr string, nativeData *NativeData, mark int) (net.Conn, error) {
	// nativeData is for Windows
	if nativeData != nil && nativeData.postConnectFunc != nil {
		defer nativeData.postConnectFunc(nativeData.handle)
	}
	d := makeDialer(mark, nativeData)

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
	listenerCfg := makeListenerConfig(mark)

	listener, err := listenerCfg.Listen(ctx, "tcp", port)

	if err != nil {
		return nil, fmt.Errorf("Failed to create listener: %s", err)
	}

	return ProxiedListener{
		netListener:    listener,
		mark:           mark,
		nativeDataCtrl: NewNativeDataControl(),
	}, nil
}

// ProxiedConnection is a proxied connection where we can recover the
// original destination.
type ProxiedConnection struct {
	originalIP            net.IP
	originalPort          int
	originalTCPConnection *net.TCPConn
	nativeData            *NativeData
}

// Native proxy/socket data (platform-specific)
type NativeData struct {
	handle          uintptr
	postConnectFunc func(fd uintptr)
}

// GetOriginalDestination sets the original destination of the connection.
func (p *ProxiedConnection) GetOriginalDestination() (net.IP, int) {
	return p.originalIP, p.originalPort
}

func (p *ProxiedConnection) GetNativeData() *NativeData {
	return p.nativeData
}

// GetTCPConnection returns the TCP connection object.
func (p *ProxiedConnection) GetTCPConnection() *net.TCPConn {
	return p.originalTCPConnection
}

// LocalAddr implements the corresponding method of net.Conn, but returns the original
// address.
func (p *ProxiedConnection) LocalAddr() net.Addr {

	return &net.TCPAddr{
		IP:   p.originalIP,
		Port: p.originalPort,
	}
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
	netListener    net.Listener
	mark           int
	nativeDataCtrl *NativeDataControl
}

type passFD interface {
	Control(func(uintptr)) error
}

func getOriginalDestination(conn *net.TCPConn) (net.IP, int, *NativeData, error) { // nolint interfacer

	rawconn, err := conn.SyscallConn()
	if err != nil {
		return nil, 0, nil, err
	}

	localIPString, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return nil, 0, nil, err
	}

	localIP := net.ParseIP(localIPString)

	return getOriginalDestPlatform(rawconn, localIP.To4() != nil)
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

	ip, port, nativeData, err := getOriginalDestination(tcpConn)
	if err != nil {
		zap.L().Error("Failed to discover original destination - aborting", zap.Error(err))
		return nil, err
	}
	l.nativeDataCtrl.StoreNativeData(ip, port, nativeData)

	return &ProxiedConnection{
		originalIP:            ip,
		originalPort:          port,
		originalTCPConnection: tcpConn,
		nativeData:            nativeData,
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

// GetInterfaces retrieves all the local interfaces.
func GetInterfaces() map[string]struct{} {
	ipmap := map[string]struct{}{}

	ifaces, err := netinterfaces.GetInterfacesInfo()
	if err != nil {
		zap.L().Error("Unable to get interfaces info", zap.Error(err))
	}

	for _, iface := range ifaces {
		for _, ip := range iface.IPs {
			ipmap[ip.String()] = struct{}{}
		}
	}

	return ipmap
}
