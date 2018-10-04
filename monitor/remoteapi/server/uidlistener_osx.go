// +build darwin windows

package server

import (
	"net"
	"time"
)

// UIDConnection is a connection wrapper that allows to recover
// the user ID of the calling process.
type UIDConnection struct {
	nc *net.UnixConn
}

// Read implements the read interface of the connection.
func (c UIDConnection) Read(b []byte) (n int, err error) {
	return c.nc.Read(b)
}

// Write implements the write interface of the connection.
func (c UIDConnection) Write(b []byte) (n int, err error) {
	return c.nc.Write(b)
}

// Close implements the close interface of the connection.
func (c UIDConnection) Close() error {
	return c.nc.Close()
}

// LocalAddr implements the LocalAddr interface of the connection.
func (c UIDConnection) LocalAddr() net.Addr {
	return c.nc.LocalAddr()
}

// RemoteAddr implements the RemoteAddr interface of the connection.
// This is the main change where we actually use the FD of the unix
// socket to find the remote UID.
func (c UIDConnection) RemoteAddr() net.Addr {
	return c.nc.RemoteAddr()
}

// SetDeadline implements the SetDeadLine interface.
func (c UIDConnection) SetDeadline(t time.Time) error {
	return c.nc.SetDeadline(t)
}

// SetReadDeadline implements the SetReadDeadling interface
func (c UIDConnection) SetReadDeadline(t time.Time) error {
	return c.nc.SetReadDeadline(t)
}

// SetWriteDeadline implements the SetWriteDeadline method of the interface.
func (c UIDConnection) SetWriteDeadline(t time.Time) error {
	return c.nc.SetWriteDeadline(t)
}

// UIDAddr implements the Addr interface and allows us to customize the address.
type UIDAddr struct {
	NetworkAddress string
	Address        string
}

// Network returns the network of the connection
func (a *UIDAddr) Network() string {
	return a.NetworkAddress
}

// String returns a string representation.
func (a *UIDAddr) String() string {
	return a.Address
}

// UIDListener is a custom net listener that uses the UID connection
type UIDListener struct {
	nl *net.UnixListener
}

// NewUIDListener creates a new listener with UID information.
func NewUIDListener(nl *net.UnixListener) *UIDListener {
	return &UIDListener{
		nl: nl,
	}
}

// Accept implements the accept method of the interface.
func (l UIDListener) Accept() (c net.Conn, err error) {
	nc, err := l.nl.AcceptUnix()
	if err != nil {
		return nil, err
	}
	return UIDConnection{nc}, nil
}

// Close implements the close method of the interface.
func (l UIDListener) Close() error {
	return l.nl.Close()
}

// Addr returns the address of the listener.
func (l UIDListener) Addr() net.Addr {
	return l.nl.Addr()
}
