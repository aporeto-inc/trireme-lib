// +build linux

package nfqdatapath

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/ghedo/go.pkt/layers"
	gpacket "github.com/ghedo/go.pkt/packet"
	"github.com/ghedo/go.pkt/packet/ipv4"
	"go.aporeto.io/enforcerd/internal/utils"
	"go.aporeto.io/enforcerd/trireme-lib/buildflags"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func procSetValue(procName string, value int) error {
	file, err := os.OpenFile(procName, os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close() // nolint: errcheck
	_, err = file.WriteString(strconv.Itoa(value))
	if err != nil {
		return err
	}
	return nil
}

// Declare function pointer so that it can be overridden by unit test
var procSetValuePtr func(procName string, value int) error = procSetValue

func adjustConntrack(mode constants.ModeType) {
	// As the pods in k8s is RO, we need to use the Host Proc to write into the proc FS.
	err := procSetValuePtr(utils.GetPathOnHostViaProcRoot("/proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal"), 1)
	if err != nil {
		zap.L().Fatal("Failed to set conntrack options", zap.Error(err))
	}

	if mode == constants.LocalServer && !buildflags.IsLegacyKernel() {
		err := procSetValuePtr(utils.GetPathOnHostViaProcRoot("/proc/sys/net/ipv4/ip_early_demux"), 0)
		if err != nil {
			zap.L().Fatal("Failed to set early demux options", zap.Error(err))
		}
	}
}

func (d *Datapath) setMark(pkt *packet.Packet, mark uint32) error {
	return nil
}

func (d *Datapath) reverseFlow(pkt *packet.Packet) error {
	return nil
}

func (d *Datapath) drop(pkt *packet.Packet) error {
	return nil
}

func (d *Datapath) dropFlow(pkt *packet.Packet) error {
	return nil
}

func (d *Datapath) ignoreFlow(pkt *packet.Packet) error {
	return nil
}

func (d *Datapath) setFlowState(pkt *packet.Packet, accepted bool) error {
	return nil
}

func (d *Datapath) startInterceptors(ctx context.Context) {
	d.startInterceptor(ctx)
}

type pingConn struct {
	conn net.Conn
}

func dialIP(srcIP, dstIP net.IP) (PingConn, error) {

	d := net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: -1, // keepalive disabled.
		LocalAddr: &net.IPAddr{IP: srcIP},
		Control:   markedconn.ControlFunc(constants.ProxyMarkInt, false, nil),
	}

	conn, err := d.Dial("ip4:tcp", dstIP.String())
	if err != nil {
		return nil, err
	}

	return &pingConn{conn: conn}, nil
}

// Close closes the connection.
func (p *pingConn) Close() error {
	return p.conn.Close()
}

// Write writes to the connection.
func (p *pingConn) Write(data []byte) (int, error) {

	n, err := p.conn.Write(data)
	if err != nil {
		return n, err
	}

	if n != len(data) {
		return n, fmt.Errorf("partial data written, total: %v, written: %v", len(data), n)
	}

	return n, nil
}

// ConstructWirePacket returns TCP packet with the given payload in wire format.
func (p *pingConn) ConstructWirePacket(srcIP, dstIP net.IP, transport gpacket.Packet, payload gpacket.Packet) ([]byte, error) {
	return packLayers(srcIP, dstIP, transport, payload)
}

func bindRandomPort(tcpConn *connection.TCPConnection) (uint16, error) {

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil || fd <= -1 {
		return 0, fmt.Errorf("unable to open socket, fd: %d : %s", fd, err)
	}

	addr := unix.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], net.ParseIP("127.0.0.1").To4())
	if err = unix.Bind(fd, &addr); err != nil {
		unix.Close(fd) // nolint: errcheck
		return 0, fmt.Errorf("unable to bind socket: %s", err)
	}

	sockAddr, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd) // nolint: errcheck
		return 0, fmt.Errorf("unable to get socket address: %s", err)
	}

	ip4Addr, ok := sockAddr.(*unix.SockaddrInet4)
	if !ok {
		unix.Close(fd) // nolint: errcheck
		return 0, fmt.Errorf("invalid socket address: %T", sockAddr)
	}

	tcpConn.PingConfig.SetSocketFd(uintptr(fd))
	return uint16(ip4Addr.Port), nil
}

func closeRandomPort(tcpConn *connection.TCPConnection) error {

	fd := tcpConn.PingConfig.SocketFd()
	tcpConn.PingConfig.SetSocketClosed(true)

	return unix.Close(int(fd))
}

func packLayers(srcIP, dstIP net.IP, transport gpacket.Packet, payload gpacket.Packet) ([]byte, error) {

	// pseudo header.
	ipPacket := ipv4.Make()
	ipPacket.SrcAddr = srcIP
	ipPacket.DstAddr = dstIP
	ipPacket.Protocol = ipv4.TCP

	transport.SetPayload(payload)  // nolint:errcheck
	ipPacket.SetPayload(transport) // nolint:errcheck

	// pack the layers together.
	buf, err := layers.Pack(transport, payload)
	if err != nil {
		return nil, fmt.Errorf("unable to encode packet to wire format: %v", err)
	}

	return buf, nil
}

func isAddrInUseErrno(errNo syscall.Errno) bool {
	return errNo == unix.EADDRINUSE
}
