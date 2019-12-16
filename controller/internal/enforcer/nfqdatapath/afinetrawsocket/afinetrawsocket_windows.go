// +build windows

package afinetrawsocket

import (
	"errors"
	"unsafe"

	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
)

type rawsocket struct {
}

// PacketMetadata is platform-specific data about the packet
type PacketMetadata struct {
	PacketInfo frontman.PacketInfo
	IgnoreFlow bool
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
	WriteSocket(buf []byte, version packet.IPver, data *PacketMetadata) error
}

// CreateSocket returns a handle to SocketWriter interface
func CreateSocket(mark int, deviceName string) (SocketWriter, error) {
	return &rawsocket{}, nil
}

func (sock *rawsocket) WriteSocket(buf []byte, version packet.IPver, data *PacketMetadata) error {
	if data == nil {
		return errors.New("no PacketMetadata for WriteSocket")
	}
	return data.udpForward(buf, version)
}

// UdpForward takes a raw udp packet and sends it to the driver to be sent on the network
func (w *PacketMetadata) udpForward(buf []byte, version packet.IPver) error {
	// set packet info.
	// could set port/addr in packet info but not required by the driver for forwarding of the packet.
	w.PacketInfo.Outbound = 1
	if version == packet.V4 {
		w.PacketInfo.Ipv4 = 1
	} else {
		w.PacketInfo.Ipv4 = 0
	}
	w.PacketInfo.PacketSize = uint32(len(buf))
	r1, _, err1 := frontman.PacketFilterForwardProc.Call(uintptr(unsafe.Pointer(&w.PacketInfo)), uintptr(unsafe.Pointer(&buf[0])))
	if r1 == 0 {
		return err1
	}
	return nil
}
