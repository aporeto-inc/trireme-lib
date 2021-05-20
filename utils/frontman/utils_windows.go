// +build windows

package frontman

import (
	"syscall"
	"unsafe"
)

// WideCharPointerToString converts a pointer to a zero-terminated wide character string to a golang string
func WideCharPointerToString(pszWide *uint16) string {

	ptr := uintptr(unsafe.Pointer(pszWide)) // nolint:govet
	buf := make([]uint16, 0, 256)
	for {
		ch := *((*uint16)(unsafe.Pointer(ptr))) // nolint:govet
		buf = append(buf, ch)
		if ch == 0 {
			break
		}

		ptr += 2
	}
	return syscall.UTF16ToString(buf)
}
