// +build darwin

package nfqdatapath

import (
	"context"
	"net"
	"syscall"

	gpacket "github.com/ghedo/go.pkt/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
)

func adjustConntrack(mode constants.ModeType) {
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
}

type pingConn struct {
}

func dialIP(srcIP, dstIP net.IP) (PingConn, error) {

	return &pingConn{}, nil
}

// Close not implemented.
func (p *pingConn) Close() error {
	return nil
}

// Write not implemented.
func (p *pingConn) Write(data []byte) (int, error) {
	return 0, nil
}

// ConstructWirePacket not implemented.
func (p *pingConn) ConstructWirePacket(srcIP, dstIP net.IP, transport gpacket.Packet, payload gpacket.Packet) ([]byte, error) {
	return nil, nil
}

func bindRandomPort(tcpConn *connection.TCPConnection) (uint16, error) {
	return 0, nil
}

func closeRandomPort(tcpConn *connection.TCPConnection) error {
	return nil
}

func isAddrInUseErrno(errNo syscall.Errno) bool {
	return false
}
