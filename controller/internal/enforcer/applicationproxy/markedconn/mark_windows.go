// +build windows

package markedconn

import (
	"net"
	"syscall"

	"go.aporeto.io/enforcerd/trireme-lib/utils/frontman"
	"go.uber.org/zap"
)

func makeListenerConfig(mark int) net.ListenConfig {
	return net.ListenConfig{}
}

// ControlFunc used in the dialer.
func ControlFunc(mark int, block bool, platformData *PlatformData) Control {

	return func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {

			if platformData == nil {
				return
			}

			// call FrontmanApplyDestHandle to update WFP redirect data before the connect() call on the new socket
			if err := frontman.Wrapper.ApplyDestHandle(fd, platformData.handle); err != nil {
				zap.L().Error("could not update proxy redirect", zap.Error(err))
			}
		})
	}
}
