// +build !windows

package nfqdatapath

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/aporeto-inc/gopkt/routing"
	"go.uber.org/zap"
)

type diagnosticsConnection struct {
	conn	   net.Conn
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
	 
	conn, err :=d.Dial("ip4:tcp", dstIP.String())
	if (err != nil) {
		return nil, err
	}
	return &diagnosticsConnection {conn = conn}, nil
}

func (diagConn* diagnosticsConnection) Close() {
	
	if diagConn.conn != nil {
		diagConn.conn.Close()
	}
}

// write writes the given data to the conn.
func (diagConn* diagnosticsConnection) Write(data []byte) error {

	n, err := diagConn.conn.Write(data)
	if err != nil {
		return err
	}

	if n != len(data) {
		return fmt.Errorf("partial data written, total: %v, written: %v", len(data), n)
	}

	return nil
}

// constructTCPPacket constructs a valid tcp packet that can be sent on wire.
func (diagConn* diagnosticsConnection)constructPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, flag tcp.Flags, tcpData []byte) ([]byte, error) {

	// pseudo header.
	// NOTE: Used only for computing checksum.
	ipPacket := ipv4.Make()
	ipPacket.SrcAddr = srcIP
	ipPacket.DstAddr = dstIP
	ipPacket.Protocol = ipv4.TCP

	// tcp.
	tcpPacket := tcp.Make()
	tcpPacket.SrcPort = srcPort
	tcpPacket.DstPort = dstPort
	tcpPacket.Flags = flag
	tcpPacket.Seq = rand.Uint32()
	tcpPacket.WindowSize = 0xAAAA
	tcpPacket.Options = []tcp.Option{
		{
			Type: tcp.MSS,
			Len:  4,
			Data: []byte{0x05, 0x8C},
		}, {
			Type: 34, // tfo
			Len:  enforcerconstants.TCPAuthenticationOptionBaseLen,
			Data: make([]byte, 2),
		},
	}
	tcpPacket.DataOff = uint8(7) // 5 (header size) + 2 * (4 byte options)

	// payload.
	payload := raw.Make()
	payload.Data = tcpData

	tcpPacket.SetPayload(payload)  // nolint:errcheck
	ipPacket.SetPayload(tcpPacket) // nolint:errcheck

	// pack the layers together.
	buf, err := layers.Pack(tcpPacket, payload)
	if err != nil {
		return nil, fmt.Errorf("unable to encode packet to wire format: %v", err)
	}

	return buf, nil
}