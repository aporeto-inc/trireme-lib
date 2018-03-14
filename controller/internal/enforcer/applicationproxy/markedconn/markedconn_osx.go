// +build darwin

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
func SocketListener(port string) (net.Listener, error) {
	return nil, nil
}
