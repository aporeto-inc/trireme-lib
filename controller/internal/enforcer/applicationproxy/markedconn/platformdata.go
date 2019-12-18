// +build !windows

package markedconn

import (
	"net"
)

// PlatformDataControl dummy impl
// PlatformDataControl is only needed for Windows now, and allows retrieval of kernel socket data.
type PlatformDataControl struct {
}

// NewPlatformDataControl returns initialized PlatformDataControl
func NewPlatformDataControl() *PlatformDataControl {
	return &PlatformDataControl{}
}

// StorePlatformData saves the data after GetDestInfo is called.
func (n *PlatformDataControl) StorePlatformData(ip net.IP, port int, platformData *PlatformData) {
}

// RemovePlatformData removes the data from storage and returns it
func RemovePlatformData(l net.Listener, conn net.Conn) *PlatformData {
	return nil
}

// TakePlatformData removes the data from storage and returns it
func TakePlatformData(l net.Listener, ip net.IP, port int) *PlatformData {
	return nil
}
