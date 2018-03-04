package tuntap

import "syscall"

// nolint
const (
	IFNAMSIZE = 16
)

type DeviceFlags uint16

// Keep names similar to what kernel headers have. I dont want to change them and make it difficult for people
// to search just make it pretty
// nolint
const (
	IFF_TUN         DeviceFlags = 0x0001
	IFF_TAP                     = 0x0002
	IFF_MULTI_QUEUE             = 0x0100
	IFF_NO_PI                   = 0x1000
)

const (
	MaxEpollEvents = 32
)

//type DeviceState uint16

const (
	IFF_UP      DeviceFlags = 0x1
	IFF_RUNNING             = 0x40
)

type ifreqDevType struct {
	ifrName  [IFNAMSIZE]byte
	ifrFlags DeviceFlags
}

type ifReqIpAddress struct {
	ifrName   [IFNAMSIZE]byte
	ipAddress syscall.RawSockaddrInet4
}
