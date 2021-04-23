// +build linux

package afinetrawsocket

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"syscall"

	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
)

type socketv4 struct {
	fd     int
	insock *syscall.SockaddrInet4
}

type socketv6 struct {
	fd     int
	insock *syscall.SockaddrInet6
}

type rawsocket struct {
	insockv4 *socketv4
	insockv6 *socketv6
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
	WriteSocket(buf []byte, version packet.IPver, data packet.PlatformMetadata) error
}

// CreateSocket returns a handle to SocketWriter interface
func CreateSocket(mark int, deviceName string) (SocketWriter, error) {
	var sockv6 *socketv6
	var sockv4 *socketv4
	var err error
	createSocketv4 := func() (*socketv4, error) {

		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
		if err != nil {
			return nil, fmt.Errorf("received error %s while open ipv4 socket", err)
		}

		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
			syscall.Close(fd) // nolint: errcheck
			return nil, fmt.Errorf("received error %s while setting socket Option SO_MARK", err)
		}

		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 0); err != nil {
			syscall.Close(fd) // nolint: errcheck
			return nil, fmt.Errorf("received error %s while setting socket Option IP_HDRINCL", err)
		}

		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DONT); err != nil {
			syscall.Close(fd) // nolint: errcheck
			return nil, fmt.Errorf("received error %s while setting socket Option IP_PMTUDISC_DONT", err)
		}

		return &socketv4{
			fd: fd,
			insock: &syscall.SockaddrInet4{
				Port: 0,
			},
		}, nil
	}

	createSocketv6 := func() (*socketv6, error) {

		fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
		if err != nil {
			return nil, fmt.Errorf("received error %s while open ipv6 socket", err)
		}

		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
			syscall.Close(fd) // nolint: errcheck
			return nil, fmt.Errorf("received error %s while setting socket Option SO_MARK", err)
		}

		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IP_HDRINCL, 0); err != nil {
			syscall.Close(fd) // nolint: errcheck
			return nil, fmt.Errorf("received error %s while setting socket Option IP_HDRINCL", err)
		}

		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER, syscall.IPV6_PMTUDISC_DONT); err != nil {
			syscall.Close(fd) // nolint: errcheck
			return nil, fmt.Errorf("received error %s while setting socket Option IP_PMTUDISC_DONT ipv6", err)
		}

		return &socketv6{
			fd: fd,
			insock: &syscall.SockaddrInet6{
				Port: 0,
			},
		}, nil
	}

	sockv4, err = createSocketv4()
	if err != nil {
		return nil, err
	}
	if IsIpv6Supported() {
		sockv6, err = createSocketv6()
		if err != nil {
			return nil, err
		}
	}
	return &rawsocket{
		insockv4: sockv4,
		insockv6: sockv6,
	}, nil
}

func (sock *rawsocket) WriteSocket(buf []byte, version packet.IPver, data packet.PlatformMetadata) error {
	// copy the dest addr
	if version == packet.V4 {
		copy(sock.insockv4.insock.Addr[:], buf[16:20])
		if err := syscall.Sendto(sock.insockv4.fd, buf[20:], 0, sock.insockv4.insock); err != nil {
			return fmt.Errorf("received error %s while sending to socket", err)
		}
	} else if sock.insockv6 != nil {

		copy(sock.insockv6.insock.Addr[:], buf[24:40])
		if err := syscall.Sendto(sock.insockv6.fd, buf[40:], 0, sock.insockv6.insock); err != nil {
			return fmt.Errorf("received error %s while sending to socket", err)
		}

	}

	return nil
}

// IsIpv6Supported returns true if the system supports ipv6 else returns false
func IsIpv6Supported() bool {
	ipv6ConfPath := "/proc/sys/net/ipv6/conf/all/disable_ipv6"
	data, err := ioutil.ReadFile(ipv6ConfPath)
	if err != nil {
		return false
	}
	val, err := strconv.Atoi(strings.Trim(string(data), "\n"))
	if err != nil {
		return false
	}
	if val == 1 {
		return false
	}
	return true
}
