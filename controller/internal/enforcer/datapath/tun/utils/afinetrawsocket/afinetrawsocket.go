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
func CreateSocket(ipaddress string, mark int, deviceName string) (SocketWriter, error) {
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark)

	err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return nil, fmt.Errorf("Received error %s while setting socket Option IP_HDRINCL", err)
	}
	insock := &syscall.SockaddrInet4{
		Port: 0,
	}
	// ip := net.ParseIP("172.17.0.1")
	// copy(insock.Addr[:], ip.To4())

	// if err := syscall.Bind(fd, insock); err != nil {
	// 	//return nil, fmt.Errorf("Received error %s while binding socket", err)
	// 	zap.L().Error("Error while binding")
	// }

	// if err = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, deviceName); err != nil {
	// 	//zap.L().Error("Unable to Bind to device ", zap.Error(err))
	// 	//return nil, fmt.Errorf("Unable to bind device %s", err)
	// }
	// TODO: Make this a const
	NfnlBuffSize := (75 * 1024)
	sockrcvbuf := 500 * int(NfnlBuffSize)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockrcvbuf)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockrcvbuf)
	lingerconf := &syscall.Linger{
		Onoff:  1,
		Linger: 0,
	}
	syscall.SetsockoptLinger(fd, syscall.SOL_SOCKET, syscall.SO_LINGER, lingerconf)

	// insock = &syscall.SockaddrInet4{
	// 	Port: 0,
	// }
	return &rawsocket{
		fd:     fd,
		insock: insock,
	}, nil

}

func (sock *rawsocket) WriteSocket(buf []byte) error {
	//This is an IP frame dest address at byte[16]
	copy(sock.insock.Addr[:], buf[16:])
	//zap.L().Error("PACKET" + string(hex.Dump(buf)))
	if err := syscall.Sendto(sock.fd, buf[:], 0, sock.insock); err != nil {
		return fmt.Errorf("received error %s while sending to socket", err)
	}
	return nil
}

func (sock *rawsocket) CloseSocket() error {
	return syscall.Close(sock.fd)
}
