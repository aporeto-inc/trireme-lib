// +build !linux

package connproc

import (
	"context"
	"net"
)

// GetOriginalDestination gets the original destination of a connection.
func GetOriginalDestination(conn net.Conn) (net.IP, int, error) {
	return []byte{}, 0, nil
}

// GetInterfaces returns the list of interfaces in this machine.
func GetInterfaces() map[string]struct{} {
	return map[string]struct{}{}
}

// Pipe creates a spliced connection
func Pipe(ctx context.Context, in, out net.Conn) error {
	return nil
}

// WriteMsg writes a message to the Fd
func WriteMsg(fd int, data []byte) error {
	return nil
}

// ReadMsg reads a message from the fd
func ReadMsg(fd int) (int, []byte, error) {
	return 0, []byte{}, nil
}

// Fd returns the file descriptor of a connection.
func Fd(c net.Conn) (int, error) {
	return 0, nil
}
