// +build windows

package markedconn

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Frontman procs needed for app proxy
// The pattern to follow is
// - call FrontmanGetDestInfo to get original ip/port
// - create new proxy socket
// - call FrontmanApplyDestHandle to update WFP redirect data
// - connect on the new proxy socket
// - free native data by calling FrontmanFreeDestHandle
var (
	driverDll           = syscall.NewLazyDLL("Frontman.dll")
	getDestInfoProc     = driverDll.NewProc("FrontmanGetDestInfo")
	applyDestHandleProc = driverDll.NewProc("FrontmanApplyDestHandle")
	freeDestHandleProc  = driverDll.NewProc("FrontmanFreeDestHandle")
	frontManOpenProc    = driverDll.NewProc("FrontmanOpenShared")
)

func getDriverHandle() (uintptr, error) {
	driverHandle, _, err := frontManOpenProc.Call()
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		return 0, fmt.Errorf("got INVALID_HANDLE_VALUE: %v", err)
	}
	return driverHandle, nil
}

// WideCharPointerToString converts a pointer to a zero-terminated wide character string to a golang string
func WideCharPointerToString(pszWide *uint16) string {

	ptr := uintptr(unsafe.Pointer(pszWide))
	buf := make([]uint16, 0, 256)
	for {
		ch := *((*uint16)(unsafe.Pointer(ptr)))
		buf = append(buf, ch)
		if ch == 0 {
			break
		}

		ptr += 2
	}
	return syscall.UTF16ToString(buf)
}
