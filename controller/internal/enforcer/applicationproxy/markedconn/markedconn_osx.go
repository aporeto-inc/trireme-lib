// +build darwin

package markedconn

import (
	"net"
)

// // MarkedTCPConn is a marked TCP connection. The mark is provided
// // during connection setup.
// type MarkedTCPConn struct {
// 	net.TCPConn
// 	mark int
// }

// // NewTCPConn returns a new TCPConnection
// func NewTCPConn(mark int) *MarkedTCPConn {
// 	return &MarkedTCPConn{
// 		TCPConn: net.TCPConn{},
// 		mark:    mark,
// 	}
// }

// DialMarkedTCP creates a new TCP connection and marks it with the provided mark.
func DialMarkedTCP(network string, laddr, raddr *net.TCPAddr, mark int) (net.Conn, error) {

	return nil, nil
}

// MarkConnection is an OSX mock
func MarkConnection(conn net.Conn, mark int) error {
	return nil
}
