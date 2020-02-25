// +build !windows

package nfqdatapath

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/aporeto-inc/gopkt/layers"
	"github.com/aporeto-inc/gopkt/packet/ipv4"
	"github.com/aporeto-inc/gopkt/packet/raw"
	"github.com/aporeto-inc/gopkt/packet/tcp"	
	"go.uber.org/zap"
)

type diagnosticsConnection struct {
	conn net.Conn
}

// dialWithMark opens raw ipv4:tcp socket and connects to the remote network.
func createConnection(srcIP, dstIP net.IP) (*diagnosticsConnection, error) {

	d := net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: -1, // keepalive disabled.
		LocalAddr: &net.IPAddr{IP: srcIP},
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 0x24, 0x40); err != nil {
					zap.L().Error("unable to assign mark", zap.Error(err))
				}
			})
		},
	}

	conn, err := d.Dial("ip4:tcp", dstIP.String())
	if err != nil {
		return nil, err
	}
	return &diagnosticsConnection{conn: conn}, nil
}

func (diagConn *diagnosticsConnection) Close() {

	if diagConn.conn != nil {
		diagConn.conn.Close()
	}
}

// write writes the given data to the conn.
func (diagConn *diagnosticsConnection) Write(data []byte) error {

	n, err := diagConn.conn.Write(data)
	if err != nil {
		return err
	}

	if n != len(data) {
		return fmt.Errorf("partial data written, total: %v, written: %v", len(data), n)
	}

	return nil
}

// constructWirePacket constructs a valid tcp packet that can be sent on wire.
func (diagConn *diagnosticsConnection) constructWirePacket(srcIP, dstIP net.IP, *tcpPacket tcp.Packet, *payload raw.Packet) ([]byte, error) {

	// pseudo header.
	// NOTE: Used only for computing checksum.
	// ip packet created here to make it easier to support Ipv6 pings later.
	ipPacket := ipv4.Make()
	ipPacket.SrcAddr = srcIP
	ipPacket.DstAddr = dstIP
	ipPacket.Protocol = ipv4.TCP
	ipPacket.SetPayload(tcpPacket) // nolint:errcheck

	// pack the layers together.
	buf, err := layers.Pack(tcpPacket, payload)
	if err != nil {
		return nil, fmt.Errorf("unable to encode packet to wire format: %v", err)
	}
	return buf, nil
}
