// +build windows

package windatapath

import (
	"fmt"
	"syscall"
	"unsafe"
)

// #cgo CFLAGS: -I .
//#include "windivert.h"
import "C"

const (
	dllname = ".\\WinDivert.dll"
)

var funcNames = [...]string{"WinDivertOpen", "WinDivertRecv", "WunDivertSend"}

type windiverthdl struct {
	hdl           *syscall.LazyDLL
	methodAddress map[string]*syscall.LazyProc
}

// WinDivertHdl is the api exposed by the windivert package driver to the datapath
type WinDivertHdl interface {
	WinDivertOpen(filter string, layer uint32, priority uint16, flags uint64) (uintptr, error)
	WinDivertRecv(data []byte, handle uintptr, recvAddr C.PWINDIVERT_ADDRESS, packetlen *uint) error                          // nolint
	WinDivertSend(lazyDll *syscall.LazyDLL, handle uintptr, data []byte, recvAddr C.PWINDIVERT_ADDRESS, writeLen *uint) error // nolint
}

func loadDLL() (*syscall.LazyDLL, error) {
	lazyDll := syscall.NewLazyDLL(dllname)
	lazyDll.Load()
	return lazyDll, nil
}

// NewWindatapath loads the dll populates the required func pointers
func NewWindatapath() (WinDivertHdl, error) {
	dllhdl, err := loadDLL()
	if err != nil {
		return nil, fmt.Errorf("Received error %s while loading dll %s", err, dllname)
	}
	winhdl := &windiverthdl{
		hdl:           dllhdl,
		methodAddress: make(map[string]*syscall.LazyProc),
	}
	for _, funcName := range funcNames {
		funcHdl := dllhdl.NewProc(funcName)
		if funcHdl != nil {
			winhdl.methodAddress[funcName] = funcHdl
			continue
		}
		return nil, fmt.Errorf("received error while loading func %s from dll %s", funcName, dllname)
	}

	return winhdl, nil
}

func (w *windiverthdl) WinDivertOpen(filter string, layer uint32, priority uint16, flags uint64) (uintptr, error) {
	addr, ok := w.methodAddress["WinDivertOpen"]
	if !ok {
		return 0, fmt.Errorf("Could not address for windivertopen")
	}
	handle, _, lastError := addr.Call(
		uintptr(unsafe.Pointer(C.CString(filter))),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	return handle, lastError
}

func (w *windiverthdl) WinDivertRecv(data []byte, handle uintptr, recvAddr C.PWINDIVERT_ADDRESS, packetlen *uint) error { // nolint
	addr, ok := w.methodAddress["WinDivertRecv"]
	if !ok {
		return fmt.Errorf("Could not address for windivertrecv")
	}
	gopacket := (*C.void)(unsafe.Pointer(&data[0]))
	_, _, lastError := addr.Call(handle,
		uintptr(unsafe.Pointer(gopacket)),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(recvAddr)),
		uintptr(unsafe.Pointer(packetlen)))
	return lastError
}

func (w *windiverthdl) WinDivertSend(lazyDll *syscall.LazyDLL, handle uintptr, data []byte, recvAddr C.PWINDIVERT_ADDRESS, writeLen *uint) error { // nolint
	addr, ok := w.methodAddress["WinDivertSend"]
	if !ok {
		return fmt.Errorf("Could not address for windivertsend")
	}

	gopacket := (*C.void)(unsafe.Pointer(&data[0]))
	_, _, lastError := addr.Call(handle,
		uintptr(unsafe.Pointer(gopacket)),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(recvAddr)),
		uintptr(unsafe.Pointer(writeLen)),
	)

	return lastError
}
