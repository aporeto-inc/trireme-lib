// +build windows

package markedconn

import (
	"fmt"
	"net"

	"github.com/sasha-s/go-deadlock"
)

// PlatformDataControl is for Windows.
// For proxied connections, we map the original ip/port to platform-specific data that needs to be retrieved
// when we make the real connection.
type PlatformDataControl struct {
	platformData map[string]*PlatformData
	mu           *deadlock.Mutex
}

// NewPlatformDataControl returns initialized PlatformDataControl
func NewPlatformDataControl() *PlatformDataControl {
	return &PlatformDataControl{
		platformData: make(map[string]*PlatformData),
		mu:           &deadlock.Mutex{},
	}
}

// StorePlatformData saves the data after GetDestInfo is called.
func (n *PlatformDataControl) StorePlatformData(ip net.IP, port int, platformData *PlatformData) {
	key := fmt.Sprintf("%s:%d", ip.String(), port)
	n.mu.Lock()
	n.platformData[key] = platformData
	n.mu.Unlock()
}

// RemovePlatformData returns the data for the given ip/port, and removes it from the map.
// The listener should be a ProxiedListener, from which we can get the ctrl.
func RemovePlatformData(l net.Listener, conn net.Conn) *PlatformData {
	n := getPlatformDataControlFromListener(l)
	if n == nil {
		return nil
	}
	if proxyConn, ok := conn.(*ProxiedConnection); ok {
		ip, port := proxyConn.GetOriginalDestination()
		return n.takePlatformData(ip, port)
	}
	return nil
}

// TakePlatformData returns the data for the given ip/port, and removes it from the map.
// The listener should be a ProxiedListener, from which we can get the ctrl.
func TakePlatformData(l net.Listener, ip net.IP, port int) *PlatformData {
	n := getPlatformDataControlFromListener(l)
	if n == nil {
		return nil
	}
	return n.takePlatformData(ip, port)
}

// takePlatformData returns the data for the given ip/port, and removes it from the map
func (n *PlatformDataControl) takePlatformData(ip net.IP, port int) *PlatformData {
	key := fmt.Sprintf("%s:%d", ip.String(), port)
	n.mu.Lock()
	nd := n.platformData[key]
	delete(n.platformData, key)
	n.mu.Unlock()
	return nd
}

// if listener is a ProxiedListener, we get its platform data ctrl
func getPlatformDataControlFromListener(l net.Listener) *PlatformDataControl {
	if proxiedL, ok := l.(ProxiedListener); ok {
		return proxiedL.platformDataCtrl
	}
	return nil
}
