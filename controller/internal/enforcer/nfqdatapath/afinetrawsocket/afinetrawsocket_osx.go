// +build !linux

package afinetrawsocket

// CreateSocket returns a handle to SocketWriter interface
func CreateSocket(mark int, deviceName string) (SocketWriter, error) {

	return nil, nil

}

// WriteSocket writes data into raw socket.
func (sock *rawsocket) WriteSocket(buf []byte) error {
	//This is an IP frame dest address at byte[16]

	return nil
}

// CloseSocket closes the raw socket.
func (sock *rawsocket) CloseSocket() error {
	return nil
}
