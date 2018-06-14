package tuntap

import "syscall"

// nolint
const (
	IFNAMSIZE = 16
)

// DeviceType is the enum for deviceType
type DeviceType int

const (
	// TUNCHARDEVICEPATH -- is the standard path of tun char device
	TUNCHARDEVICEPATH = "/dev/net/tun"
)

// nolint
const (
	// unsupported --  just a delimiter for invalid device type
	unsupported DeviceType = iota

	// TUNDEVICE -- tun device ( this will give ip frames)
	TUNDEVICE DeviceType = 1

	// TAPDEVICE -- tap device ( this will give ethernet frames). Currently not implemented here
	TAPDEVICE DeviceType = 2
)

// DeviceFlags for flags accepted by the ioctl to create TUN/TAP device
type DeviceFlags uint16

// Keep names similar to what kernel headers have. I dont want to change them and make it difficult for people
// to search just make it pretty
// nolint
const (
	IFF_TUN         DeviceFlags = 0x0001
	IFF_TAP                     = 0x0002 // nolint
	IFF_MULTI_QUEUE             = 0x0100
	IFF_NO_PI                   = 0x1000
)

const (
	//MaxEpollEvents the maximum set size we plan to use to Epoll
	MaxEpollEvents = 32
)

// nolint
const (
	IFF_UP      DeviceFlags = 0x1
	IFF_RUNNING             = 0x40
)

type ifreqDevType struct {
	ifrName  [IFNAMSIZE]byte
	ifrFlags DeviceFlags
}

type ifReqIPAddress struct {
	ifrName   [IFNAMSIZE]byte
	ipAddress syscall.RawSockaddrInet4
}

// SpliceSocket is an interface which implements the socket writer.
type SpliceSocket interface {
	CreateSocket() error
	WriteSocket(data []byte)
}
