// +build !windows

package markedconn

import (
	"net"
)

// NativeDataControl dummy impl
type NativeDataControl struct {
}

func NewNativeDataControl() *NativeDataControl {
	return &NativeDataControl{}
}

func (n *NativeDataControl) StoreNativeData(ip net.IP, port int, nativeData *NativeData) {
}

func RemoveNativeData(l net.Listener, conn net.Conn) *NativeData {
	return nil
}

func TakeNativeData(l net.Listener, ip net.IP, port int) *NativeData {
	return nil
}
