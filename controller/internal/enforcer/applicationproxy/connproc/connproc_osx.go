// +build !linux

package connproc

import "net"

// GetOriginalDestination gets the original destination of a connection.
func GetOriginalDestination(conn net.Conn) (net.IP, int, error) {
	return []byte{}, 0, nil
}

// GetInterfaces returns the list of interfaces in this machine.
func GetInterfaces() map[string]struct{} {
	return map[string]struct{}{}
}
