// +build darwin

package afinetrawsocket

import "go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"

const (
	// RawSocketMark is the mark asserted on all packet sent out of this socket
	RawSocketMark = 0x63
	// NetworkRawSocketMark is the mark on packet egressing
	//the raw socket coming in from network
	NetworkRawSocketMark = 0x40000063
	//ApplicationRawSocketMark is the mark on packet egressing
	//the raw socket coming from application
	ApplicationRawSocketMark = 0x40000062
)

// SocketWriter interface exposes an interface to write and close sockets
type SocketWriter interface {
	WriteSocket(buf []byte, version packet.IPver, data packet.PlatformMetadata) error
	CloseSocket() error
}

type rawsocket struct { // nolint
}

// CreateSocket returns a handle to SocketWriter interface
func CreateSocket(mark int, deviceName string) (SocketWriter, error) {
	return nil, nil
}

// WriteSocket writes data into raw socket.
func (sock *rawsocket) WriteSocket(buf []byte, version packet.IPver, data packet.PlatformMetadata) error {
	//This is an IP frame dest address at byte[16]

	return nil
}

// CloseSocket closes the raw socket.
func (sock *rawsocket) CloseSocket() error {
	return nil
}
