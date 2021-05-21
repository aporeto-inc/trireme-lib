// +build linux

package markedconn

import (
	"net"
	"syscall"

	"go.uber.org/zap"
)

func makeListenerConfig(mark int) net.ListenConfig {
	return net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
					zap.L().Error("Failed to mark connection", zap.Error(err))
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_TCP, 23, 16*1024); err != nil {
					zap.L().Error("Cannot set tcp fast open options", zap.Error(err))
				}
			})
		},
	}
}

// ControlFunc used in the dialer.
func ControlFunc(mark int, block bool, platformData *PlatformData) Control {

	return func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {

			if err := syscall.SetNonblock(int(fd), !block); err != nil {
				zap.L().Error("unable to set socket options", zap.Error(err))
			}
			if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
				zap.L().Error("Failed to assing mark to socket", zap.Error(err))
			}
			if err := syscall.SetsockoptInt(int(fd), syscall.SOL_TCP, 30, 1); err != nil {
				zap.L().Debug("Failed to set fast open socket option", zap.Error(err))
			}
		})
	}
}
