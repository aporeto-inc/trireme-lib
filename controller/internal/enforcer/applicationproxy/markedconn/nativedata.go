// +build !windows

package markedconn

import (
	"net"
)

// NativeDataControl dummy impl
type NativeDataControl struct {
}

// NewNativeDataControl returns initialized NativeDataControl
func NewNativeDataControl() *NativeDataControl {
	return &NativeDataControl{}
}

// StoreNativeData saves the data after GetDestInfo is called.
func (n *NativeDataControl) StoreNativeData(ip net.IP, port int, nativeData *NativeData) {
}

// RemoveNativeData removes the data from storage and returns it
func RemoveNativeData(l net.Listener, conn net.Conn) *NativeData {
	return nil
}

// TakeNativeData removes the data from storage and returns it
func TakeNativeData(l net.Listener, ip net.IP, port int) *NativeData {
	return nil
}
