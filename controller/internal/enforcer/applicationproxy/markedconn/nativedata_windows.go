// +build windows

package markedconn

import (
	"fmt"
	"net"
	"sync"
)

// NativeDataControl is for Windows.
// For proxied connections, we map the original ip/port to native data that needs to be retrieved
// when we make the real connection.
type NativeDataControl struct {
	nativeData map[string]*NativeData
	mu         *sync.Mutex
}

// NewNativeDataControl returns initialized NativeDataControl
func NewNativeDataControl() *NativeDataControl {
	return &NativeDataControl{
		nativeData: make(map[string]*NativeData),
		mu:         &sync.Mutex{},
	}
}

// StoreNativeData saves the data after GetDestInfo is called.
func (n *NativeDataControl) StoreNativeData(ip net.IP, port int, nativeData *NativeData) {
	if n.nativeData != nil {
		key := fmt.Sprintf("%s:%d", ip.String(), port)
		n.mu.Lock()
		defer n.mu.Unlock()
		n.nativeData[key] = nativeData
	}
}

// RemoveNativeData returns the data for the given ip/port, and removes it from the map.
// The listener should be a ProxiedListener, from which we can get the ctrl.
func RemoveNativeData(l net.Listener, conn net.Conn) *NativeData {
	n := getNativeDataControlFromListener(l)
	if n == nil {
		return nil
	}
	if proxyConn, ok := conn.(*ProxiedConnection); ok {
		ip, port := proxyConn.GetOriginalDestination()
		return n.takeNativeData(ip, port)
	}
	return nil
}

// TakeNativeData returns the data for the given ip/port, and removes it from the map.
// The listener should be a ProxiedListener, from which we can get the ctrl.
func TakeNativeData(l net.Listener, ip net.IP, port int) *NativeData {
	n := getNativeDataControlFromListener(l)
	if n == nil {
		return nil
	}
	return n.takeNativeData(ip, port)
}

// takeNativeData returns the data for the given ip/port, and removes it from the map
func (n *NativeDataControl) takeNativeData(ip net.IP, port int) *NativeData {
	if n.nativeData != nil {
		key := fmt.Sprintf("%s:%d", ip.String(), port)
		n.mu.Lock()
		defer n.mu.Unlock()
		nd := n.nativeData[key]
		delete(n.nativeData, key)
		return nd
	}
	return nil
}

// if listener is a ProxiedListener, we get its native data ctrl
func getNativeDataControlFromListener(l net.Listener) *NativeDataControl {
	if proxiedL, ok := l.(ProxiedListener); ok {
		return proxiedL.nativeDataCtrl
	}
	return nil
}
