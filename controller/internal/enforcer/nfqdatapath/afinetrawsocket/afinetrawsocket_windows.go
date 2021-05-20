// +build windows

package afinetrawsocket

import (
	"errors"

	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/utils/frontman"
)

type rawsocket struct {
}

// WindowPlatformMetadata is platform-specific data about the packet
type WindowPlatformMetadata struct {
	PacketInfo frontman.PacketInfo
	IgnoreFlow bool
	DropFlow   bool
	Drop       bool
	SetMark    uint32
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
	return &rawsocket{}, nil
}

// WriteSocket on Windows calls into the driver to forward the packet
func (sock *rawsocket) WriteSocket(buf []byte, version packet.IPver, data packet.PlatformMetadata) error {
	if data == nil {
		return errors.New("no PlatformMetadata for WriteSocket")
	}
	windata, ok := data.(*WindowPlatformMetadata)
	if !ok {
		return errors.New("no WindowPlatformMetadata for WriteSocket")
	}
	return windata.forwardPacket(buf, version)
}

// Clone the WindowPlatformMetadata structure
func (w *WindowPlatformMetadata) Clone() packet.PlatformMetadata {
	platformMetadata := &WindowPlatformMetadata{
		PacketInfo: w.PacketInfo,
		IgnoreFlow: w.IgnoreFlow,
		Drop:       w.Drop,
	}
	return platformMetadata
}

// forwardPacket takes a raw packet and sends it to the driver to be sent on the network
func (w *WindowPlatformMetadata) forwardPacket(buf []byte, version packet.IPver) error {

	if w.IgnoreFlow && w.DropFlow {
		return errors.New("ignoreFlow and dropFlow cannot both be true")
	}

	// Could set port/addr in packet info but not required by the driver for forwarding of the packet.
	// Create a copy of the packet info so that these changes don't modifiy the current PacketInfo
	packetInfo := w.PacketInfo
	packetInfo.Outbound = 1
	packetInfo.NewPacket = 1
	packetInfo.Drop = 0
	packetInfo.IgnoreFlow = 0
	if version == packet.V4 {
		packetInfo.Ipv4 = 1
	} else {
		packetInfo.Ipv4 = 0
	}
	if w.Drop {
		packetInfo.Drop = 1
	}
	if w.IgnoreFlow {
		packetInfo.IgnoreFlow = 1
	}
	if w.DropFlow {
		packetInfo.DropFlow = 1
	}
	packetInfo.PacketSize = uint32(len(buf))
	if err := frontman.Wrapper.PacketFilterForward(&packetInfo, buf); err != nil {
		return err
	}
	return nil
}
