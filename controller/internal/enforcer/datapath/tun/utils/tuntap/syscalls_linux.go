package tuntap

import (
	"os"
	"syscall"
)

func ioctl(fd uintptr, request int, argp uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(request), argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}

// Wrapper around syscall
func read(fd int, data []byte) (int, error) {
	return syscall.Read(fd, data)
}

// Write wrapper around the Write syscall
func Write(fd int, data []byte) (int, error) {
	return syscall.Write(fd, data)
}
