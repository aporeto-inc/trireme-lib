// +build linux

package afinetrawsocket

import (
	"fmt"
	"syscall"
)

type rawsocket struct {
	fd     int
	insock *syscall.SockaddrInet4
}

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
	WriteSocket(buf []byte) error
	CloseSocket() error
}

// CreateSocket returns a handle to SocketWriter interface
func CreateSocket(mark int, deviceName string) (SocketWriter, error) {
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
		syscall.Close(fd) // nolint
		return nil, fmt.Errorf("Received error %s while setting socket Option SO_MARK", err)
	}

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd) // nolint
		return nil, fmt.Errorf("Received error %s while setting socket Option IP_HDRINCL", err)
	}
	insock := &syscall.SockaddrInet4{
		Port: 0,
	}

	return &rawsocket{
		fd:     fd,
		insock: insock,
	}, nil

}

func (sock *rawsocket) WriteSocket(buf []byte) error {
	//This is an IP frame dest address at byte[16]
	copy(sock.insock.Addr[:], buf[16:20])
	if err := syscall.Sendto(sock.fd, buf[:], 0, sock.insock); err != nil {
		return fmt.Errorf("received error %s while sending to socket", err)
	}
	return nil
}

func (sock *rawsocket) CloseSocket() error {
	return syscall.Close(sock.fd)
}
